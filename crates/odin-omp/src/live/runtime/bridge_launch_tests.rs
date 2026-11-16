//! Covers declaration projection and production launch arguments. These tests
//! do not execute the harness or observe a provider's model request.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use odin_atlas::AtlasSources;
use odin_domain::huginn::{LiveError, LiveSessionId, ModelName, ProviderName, SessionManifest};
use odin_domain::operation::Limits;
use odin_domain::{Digest, LaneId, NodeId, ProjectId, SeatId, SliceId};
use odin_kernel::{MintRequest, TokenIssuer};
use odin_ledger::Ledger;
use odin_registry::{ObjectConfig, RegistryObject};
use uuid::Uuid;

use crate::host_tools::delegation::DelegationLinkLedger;
use crate::host_tools::operations::{
    seat_operation_policy, wall_clock, ProvisionedFreshAuthorityProvider, RevisionMaterialSource,
    SeatOperationPolicyInputs, SessionOperationBinding, StaticSchemaCatalog,
};
use crate::live::ledger::fs::FsLiveLedger;
use crate::live::ledger::LiveLedger;
use crate::live::supervisor::BridgeRuntimeFactory;
use crate::process::{
    launch_for_fixture, OmpProcessSpec, RemoteAttachError, RemoteHarnessAdmission,
    RemoteHarnessChannel, RemoteHarnessFactory,
};

use super::{
    ProductionBridgeRuntimeConfig, ProductionBridgeRuntimeFactory, SessionCapsuleAuthority,
    WorkloadCarrierPort,
};

/// An arbitrary seat id that appears nowhere in production policy: if
/// any branch special-cased a seat name, this composition would not carry
/// the declared guidance.
const SEAT: &str = "herald";
const PROJECT: &str = "odin";
const LANE: &str = "herald.session";
const PROVIDER: &str = "gateway";
const MODEL: &str = "herald-model";
const SWITCH_MODEL: &str = "herald-switch-model";
const GUIDANCE: &str = "Keep replies short and casual. When a request has several \
parts, ask one quick clarifying question before acting.";
/// The declared workload profile id the brief-guidance fixture admits.
const WORKLOAD_PROFILE: &str = "herald-task";
/// The Atlas source the knowledge fixture policy authorizes.
const BRAIN_SOURCE: &str = "atlas:herald";

struct Composition {
    factory: ProductionBridgeRuntimeFactory,
    live: Arc<FsLiveLedger>,
    manifest: SessionManifest,
    _dirs: Vec<tempfile::TempDir>,
}

/// A declared conversation seat under an arbitrary registry id, parsed
/// through the strict seat schema exactly like a published registry
/// object.
fn declared_seat(id: &str, with_conversation: bool) -> RegistryObject {
    let vehicle = if with_conversation {
        format!(
            "\n[conversation]\nproject = \"{PROJECT}\"\nask_capability = \"seat.ask.{id}\"\n\
             guidance = \"{GUIDANCE}\"\nanswer_timeout_seconds = 240\n"
        )
    } else {
        String::new()
    };
    declared_seat_with_vehicle(id, &vehicle)
}

fn declared_seat_with_vehicle(id: &str, vehicle: &str) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "conversation projection fixture"
categories = []
tool_refs = []
project_scope = ["{PROJECT}"]
brain_scope = []
limits = {{ max_parallel_runs = 2, max_sessions = 4, budget = {{ usd_micros = 1000000, window = {{ duration_seconds = 2592000 }} }} }}
knowledge = {{ atlas_sources = [], required_tags = [], denied_tags = [], top_k = 16 }}
context = {{ max_bundle_tokens = 24576, profile = "fixture" }}
tools = {{ deny = [], redirects = {{ max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [] }} }}
{vehicle}
"#
    );
    RegistryObject {
        id: id.to_owned(),
        relative_config: std::path::PathBuf::from(format!("registry/seats/{id}/seat.toml")),
        config: ObjectConfig::Seat(Box::new(
            toml::from_str(&source).expect("declared seat parses"),
        )),
    }
}

struct AcceptingCapsules;

impl SessionCapsuleAuthority for AcceptingCapsules {
    fn open_session(
        &self,
        _session: &odin_domain::SessionId,
        _binding: &SessionOperationBinding,
        capsule_root: &Path,
    ) -> Result<std::path::PathBuf, LiveError> {
        Ok(capsule_root.to_path_buf())
    }
}

/// A capsule authority that opens every session onto one capsule directory.
struct CapsuleAt(std::path::PathBuf);

impl SessionCapsuleAuthority for CapsuleAt {
    fn open_session(
        &self,
        _session: &odin_domain::SessionId,
        _binding: &SessionOperationBinding,
        _capsule_root: &Path,
    ) -> Result<std::path::PathBuf, LiveError> {
        std::fs::create_dir_all(&self.0).expect("capsule directory");
        Ok(self.0.clone())
    }
}

/// The store path of `name` on the test PATH: the shell bubble binds only
/// the store, so a profile symlink would not resolve inside it.
fn store_tool(name: &str) -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .find(|dir| dir.join(name).is_file())
        .and_then(|dir| std::fs::canonicalize(dir).ok())
        .map(|dir| dir.join(name))
        .unwrap_or_else(|| panic!("{name} is not on the test PATH"))
}

fn host_sandbox() -> crate::process::SeatSandboxHost {
    let coreutils = store_tool("env");
    crate::process::SeatSandboxHost {
        bwrap: store_tool("bwrap"),
        bash: store_tool("bash"),
        python: None,
        models_file: None,
        provider_auth: Vec::new(),
        omp_state: Vec::new(),
        etc_files: Vec::new(),
        path_extra: vec![coreutils.parent().expect("coreutils bin").to_path_buf()],
    }
}

/// The never-attached carrier fixture: `build` reads its process spec; an
/// attach refuses typed (live argv carriage: bridge tests `remote_launch`).
struct UnattachedCarrier {
    spec: OmpProcessSpec,
    job_worker: odin_types::WorkerId,
    admission: RemoteHarnessAdmission,
}

#[async_trait::async_trait]
impl RemoteHarnessFactory for UnattachedCarrier {
    async fn attach(
        &self,
        _args: &[String],
        _env: &[(String, String)],
    ) -> Result<RemoteHarnessChannel, RemoteAttachError> {
        Err(RemoteAttachError {
            detail: "the launch-argument fixture never attaches a carrier".to_owned(),
        })
    }

    fn job_worker_id(&self) -> &odin_types::WorkerId {
        &self.job_worker
    }

    fn stop_action(&self) -> odin_ledger::stop::JobStopAction {
        odin_ledger::stop::JobStopAction::Delete
    }

    fn admission(&self) -> &RemoteHarnessAdmission {
        &self.admission
    }

    fn process_spec(&self) -> OmpProcessSpec {
        self.spec.clone()
    }
}

/// The never-attached carrier resolver fixture for the admitted manifest.
struct FixtureCarrierPort;

#[async_trait::async_trait]
impl WorkloadCarrierPort for FixtureCarrierPort {
    async fn carrier_for(
        &self,
        _binding: &odin_domain::huginn::WorkloadSessionBinding,
        _manifest: &SessionManifest,
    ) -> Result<Arc<dyn RemoteHarnessFactory>, LiveError> {
        let executable = std::env::temp_dir().join(format!(
            "odin-workload-launch-fixture-omp-{}",
            std::process::id()
        ));
        Ok(Arc::new(UnattachedCarrier {
            job_worker: odin_types::WorkerId::new("worker-workload-launch-fixture")
                .expect("worker id"),
            admission: RemoteHarnessAdmission {
                profile: WORKLOAD_PROFILE.to_owned(),
                image: "fixture.invalid/odin-workload:fixture".to_owned(),
            },
            spec: OmpProcessSpec {
                executable: executable.clone(),
                cwd: std::env::temp_dir(),
                explicit_args: vec![
                    "workload-exec".to_owned(),
                    "--agent-dir".to_owned(),
                    "/state/.omp-agent/fixture-operation".to_owned(),
                    "--working-dir".to_owned(),
                    "/state".to_owned(),
                    "--trusted-extension".to_owned(),
                    executable.with_extension("js").display().to_string(),
                    "--".to_owned(),
                    executable.display().to_string(),
                    "--trusted-extension".to_owned(),
                    executable.with_extension("js").display().to_string(),
                ],
                explicit_env: vec![(
                    "PI_CODING_AGENT_DIR".to_owned(),
                    "/state/.omp-agent/fixture-operation".to_owned(),
                )],
                expected_source_revision: crate::probe::PINNED_OMP_SOURCE_REVISION.to_owned(),
                startup_timeout: Duration::from_secs(30),
                drain_timeout: Duration::from_secs(5),
                kill_timeout: Duration::from_secs(1),
            },
        }))
    }
}

/// The conversation-only fixture: no workload manifest.
fn compose(objects: &[RegistryObject], poison_base_prompt: Option<&str>) -> Composition {
    compose_inner(objects, poison_base_prompt, None, false, false, None)
}

/// The workload fixture: admits a manifest bound to [`WORKLOAD_PROFILE`],
/// carried by the never-attached carrier, with no composed session laws.
fn compose_with(
    objects: &[RegistryObject],
    poison_base_prompt: Option<&str>,
    workload_manifest: bool,
) -> Composition {
    compose_inner(
        objects,
        poison_base_prompt,
        None,
        workload_manifest,
        false,
        None,
    )
}

/// The full fixture: an optional resolved brain policy for the seat plus
/// the optional workload manifest and poisoned budget environment.
fn compose_inner(
    objects: &[RegistryObject],
    poison_base_prompt: Option<&str>,
    brain_policy: Option<odin_brain::config::EffectiveBrainPolicy>,
    workload_manifest: bool,
    poison_budget_env: bool,
    sphere: Option<crate::process::SphereProjection>,
) -> Composition {
    compose_fixture(
        objects,
        poison_base_prompt,
        brain_policy,
        (workload_manifest, false),
        poison_budget_env,
        false,
        sphere,
    )
}

/// `sandboxed`: the seat declares a shell writing `capsule` and `scratch`,
/// launched through this host's real bwrap and bash, and the session's
/// capsule is `capsule/` beside the declared `project/` root. `sphere`,
/// when present, replaces the seat's path roles for this project's lane.
fn compose_fixture(
    objects: &[RegistryObject],
    poison_base_prompt: Option<&str>,
    brain_policy: Option<odin_brain::config::EffectiveBrainPolicy>,
    workload: (bool, bool),
    poison_budget_env: bool,
    sandboxed: bool,
    sphere: Option<crate::process::SphereProjection>,
) -> Composition {
    let (workload_manifest, workload_law) = workload;
    // Only a seat with a brain policy reads the store, and starting one costs about a second.
    let needs_brain_store = brain_policy.is_some();
    let dirs: Vec<tempfile::TempDir> = (0..4)
        .map(|_| tempfile::tempdir().expect("tempdir"))
        .collect();
    let executable = dirs[0].path().join("omp");
    std::fs::write(&executable, b"").expect("fixture executable");
    let extension = dirs[0].path().join("extension.js");
    for source in ["crates", "extension", "registry", "skeletons"] {
        std::fs::create_dir_all(dirs[1].path().join(source)).expect("atlas source root");
    }
    let bridge_root = dirs[2].path().join("bridge-ledger");
    let live_root = dirs[2].path().join("live-ledger");
    let links_root = dirs[2].path().join("delegation-links");
    std::fs::create_dir_all(&bridge_root).expect("bridge ledger root");
    std::fs::create_dir_all(&live_root).expect("live ledger root");
    std::fs::create_dir_all(&links_root).expect("delegation links root");
    let artifact_root = dirs[3].path().join("artifacts");
    let hooks_root = dirs[3].path().join("hooks");
    let project_root = dirs[3].path().join("project");
    std::fs::create_dir_all(&project_root).expect("project root");

    let mut base_args = crate::process::governed_harness_args(&extension);
    if let Some(flag) = poison_base_prompt {
        base_args.push(flag.to_owned());
        base_args.push("undeclared base law".to_owned());
    }
    let mut base_env = vec![("HOME".to_owned(), dirs[0].path().display().to_string())];
    if poison_budget_env {
        base_env.push((
            "ODIN_CONTEXT_BUDGET".to_owned(),
            "gateway|smuggled-model|1|0".to_owned(),
        ));
    }
    let process = OmpProcessSpec {
        executable: executable.clone(),
        cwd: dirs[0].path().to_path_buf(),
        explicit_args: base_args,
        explicit_env: base_env,
        expected_source_revision: crate::probe::PINNED_OMP_SOURCE_REVISION.to_owned(),
        startup_timeout: Duration::from_secs(30),
        drain_timeout: Duration::from_secs(5),
        kill_timeout: Duration::from_secs(1),
    };
    let live: Arc<FsLiveLedger> = Arc::new(FsLiveLedger::open(&live_root).expect("live ledger"));
    let seat = SeatId::new(SEAT).expect("seat id");
    let lane = LaneId::new(LANE).expect("lane id");
    let project = ProjectId::new(PROJECT).expect("project id");
    let policy = seat_operation_policy(SeatOperationPolicyInputs {
        seat_id: seat.clone(),
        slice_id: SliceId::new("herald.slice").expect("slice id"),
        lane_id: lane.clone(),
        seat_revision: Digest::new([7; 32]),
        slice_revision: Digest::new([9; 32]),
        admission: Digest::new([1; 32]),
        seat_tool_refs: BTreeSet::new(),
        slice_capabilities: BTreeSet::new(),
        project_capabilities: BTreeSet::new(),
        lane_capabilities: BTreeSet::new(),
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        resource_constraints: BTreeMap::new(),
        seat_categories: BTreeSet::new(),
    });
    let session_uuid = Uuid::new_v4();
    let bridge_session = odin_domain::SessionId::new(session_uuid.to_string()).expect("session id");
    // Real provisioned authority for the generation-scoped factory build:
    // the fixture mints one revision-bound token over the seat policy it
    // declares, and a one-generation material source pins revision 1.
    let authority_root = bridge_root.join("authority-tokens");
    std::fs::create_dir_all(&authority_root).expect("authority token root");
    let signing_key = crate::host_tools::operations::generate_signing_key();
    let token = TokenIssuer::new(signing_key.clone())
        .expect("token issuer")
        .mint_bound(
            MintRequest {
                seat: seat.clone(),
                slice: SliceId::new("herald.slice").expect("slice id"),
                lane: lane.clone(),
                session: bridge_session.clone(),
                seat_revision: Digest::new([7; 32]),
                slice_revision: Digest::new([9; 32]),
                capability_policy_digest: Digest::new([1; 32]),
                context_policy_digest: policy.context_policy_digest,
                issued_at_ms: 0,
                expires_at_ms: u64::MAX,
                entropy: b"bridge-launch generation fixture",
            },
            1,
        )
        .expect("mint bridge launch token");
    std::fs::write(
        authority_root.join(format!("{}.json", bridge_session.as_str())),
        serde_json::to_vec(&token).expect("encode bridge launch token"),
    )
    .expect("write bridge launch token");
    let material_source: Arc<dyn RevisionMaterialSource> = Arc::new(BridgeFixtureMaterial {
        material: crate::host_tools::operations::RevisionMaterial {
            revision: 1,
            contracts: Arc::new(BTreeMap::new()),
            admission_digest: Digest::new([1; 32]),
            seat_operation_bindings: BTreeMap::from([(
                (seat.clone(), lane.clone()),
                policy.clone(),
            )]),
            session_lanes: BTreeMap::from([((seat.clone(), project.clone()), lane.clone())]),
            tool_index: BTreeMap::new(),
            contract_adapters: BTreeSet::new(),
            declaration_decided: BTreeSet::new(),
            escalation_targets: Default::default(),
        },
    });
    // The seat's serving model declares its window, as odind derives it,
    // beside a second declared launch option the seat may switch to.
    let lane_windows_by_seat: BTreeMap<SeatId, Vec<super::LaneWindow>> = brain_policy
        .as_ref()
        .map(|policy| {
            let serving = super::LaneWindow {
                provider: PROVIDER.to_owned(),
                model: policy.model.name.as_str().to_owned(),
                window: policy.model.context_window_tokens,
                tokenizer: policy.model.tokenizer.clone(),
            };
            let switchable = super::LaneWindow {
                provider: PROVIDER.to_owned(),
                model: SWITCH_MODEL.to_owned(),
                window: std::num::NonZeroU32::new(20_000).expect("window"),
                tokenizer: odin_domain::knowledge::ids::TokenizerId::new(
                    "odin.tokenizer.utf8-bytes.v1",
                )
                .expect("byte tokenizer id"),
            };
            BTreeMap::from([(
                SeatId::new(SEAT).expect("seat id"),
                vec![serving, switchable],
            )])
        })
        .unwrap_or_default();
    let config = ProductionBridgeRuntimeConfig {
        tool_result_budgets: BTreeMap::new(),
        workload_drafts: None,
        task_grants: None,
        approved_calls: None,
        root_plan_consent: None,
        jobs: None,
        delivery_acknowledger: None,
        process,
        worker: launch_for_fixture(&executable),
        bridge_ledger: Arc::new(Mutex::new(
            Ledger::open(bridge_root.join("ledger.sqlite3")).expect("bridge ledger"),
        )),
        live_ledger: Arc::clone(&live) as Arc<dyn LiveLedger>,
        atlas: Arc::new(OnceLock::from(Arc::new(
            odin_atlas::build(AtlasSources::new(dirs[1].path())).expect("atlas composes"),
        ))),
        allowed_atlas_scope: odin_atlas::AtlasScope::default(),
        brain_policies: brain_policy
            .map(|policy| BTreeMap::from([(SeatId::new(SEAT).expect("seat id"), policy)]))
            .unwrap_or_default(),
        brain_sources: BTreeMap::from([(
            odin_domain::knowledge::ids::AtlasId::new(BRAIN_SOURCE).expect("atlas id"),
            odin_brain::service::BrainSourceConfig::Atlas {
                root: dirs[1].path().to_path_buf(),
            },
        )]),
        brain_embedding: None,
        brain_embedding_model: None,
        brain_postgres: needs_brain_store.then(odin_brain::test_cluster::TestCluster::thread_store),
        brain_rerank: None,
        artifact_root,
        promotion_verifier: None,
        campaign_validator: None,
        spend_validator: None,
        campaign_recorder: None,
        spend_recorder: None,
        context_trace_root: None,
        max_artifact_read_bytes: 4096,
        project_roots: BTreeMap::from([(project.clone(), project_root)]),
        session_lanes: BTreeMap::from([((seat.clone(), project), lane.clone())]),
        allowed_nodes: BTreeSet::from([NodeId::new("laptop").expect("node id")]),
        read_only: false,
        owner_id: "conversation-projection-test".to_owned(),
        hooks_root,
        lease_ttl: Duration::from_secs(60),
        zellij: None,
        operation_contracts: BTreeMap::new(),
        admission_revision: 1,
        schema_catalog: Arc::new(StaticSchemaCatalog::new(Vec::new()).expect("schema catalog")),
        operation_limits: Limits::new(u64::MAX, u64::MAX, u64::MAX),
        operation_clock: wall_clock(),
        task_slot: None,
        operation_authority_provider: Arc::new(
            ProvisionedFreshAuthorityProvider::open(authority_root, signing_key)
                .expect("open bridge launch authority provider"),
        ),
        revision_material: material_source,
        adapters: Arc::new(crate::host_tools::adapter::DeclaredAdapterBackends::none()),
        adapter_status_ttl: Duration::from_secs(1),
        session_capsule_authority: match sandboxed {
            true => Arc::new(CapsuleAt(dirs[3].path().join("capsule"))),
            false => Arc::new(AcceptingCapsules),
        },
        seat_operation_bindings: BTreeMap::from([((seat, lane), policy)]),
        delegation_links: DelegationLinkLedger::open(&links_root).expect("delegation links"),
        rollover_by_seat: BTreeMap::new(),
        lane_windows_by_seat,
        card_windows: Default::default(),
        conversation_guidance: super::declared_conversation_guidance(objects)
            .expect("guidance projection"),
        toolsets: odin_registry::toolsets::declared_toolsets(objects),
        deferred_toolsets: odin_registry::toolsets::declared_deferrals(objects),
        workload_sessions: if workload_law {
            BTreeMap::from([(
                WORKLOAD_PROFILE.to_owned(),
                super::WorkloadSessionLaw {
                    brief: "Retain prior task turns on recovery".to_owned(),
                    memory_namespace: odin_domain::knowledge::ids::AtlasId::new("atlas.crates")
                        .expect("memory namespace"),
                    max_facts: 4,
                    tools: BTreeSet::new(),
                },
            )])
        } else {
            BTreeMap::new()
        },
        workload_carrier: workload_manifest
            .then(|| Arc::new(FixtureCarrierPort) as Arc<dyn WorkloadCarrierPort>),
        context_read: None,
        device_run: None,
        operator_capabilities: BTreeSet::new(),
        hermes_tools: Vec::new(),
        turn_images: None,
        hermes_internal_bindings: Vec::new(),
        seat_read_roots: BTreeMap::new(),
        seat_sandboxes: match sandboxed {
            true => BTreeMap::from([(
                SeatId::new(SEAT).expect("seat id"),
                odin_registry::schema::SeatSandboxToml {
                    shell: true,
                    network: odin_registry::schema::SeatSandboxNetwork::None,
                    writable: vec!["capsule".to_owned(), "scratch".to_owned()],
                    readonly: Vec::new(),
                },
            )]),
            false => BTreeMap::new(),
        },
        seat_memory_max: super::declared_seat_memory_max(objects),
        project_spheres: sphere
            .map(|sphere| BTreeMap::from([(ProjectId::new(PROJECT).expect("project id"), sphere)]))
            .unwrap_or_default(),
        sandbox_host: sandboxed.then(host_sandbox),
    };
    let enabled: Vec<odin_registry::AdmittedBinding> = Vec::new();
    let factory = ProductionBridgeRuntimeFactory::restricted(config, enabled)
        .expect("the production factory composes");
    let manifest = SessionManifest {
        session_id: LiveSessionId::new(session_uuid).expect("session id"),
        seat_id: SeatId::new(SEAT).expect("seat id"),
        slice_id: SliceId::new("herald.slice").expect("slice id"),
        project_id: ProjectId::new(PROJECT).expect("project id"),
        provider: ProviderName::new(PROVIDER).expect("provider name"),
        model: ModelName::new(MODEL).expect("model name"),
        title: None,
        target_node: NodeId::new("laptop").expect("node id"),
        open_tab: false,
        workload: workload_manifest.then(|| odin_domain::huginn::WorkloadSessionBinding {
            profile: WORKLOAD_PROFILE.to_owned(),
            snapshot_revision: 1,
            operation: "fixture-operation".to_owned(),
            inputs: Vec::new(),
            launching_run: None,
            unresolved_hosts: Default::default(),
            limits: None,
            seeds: Vec::new(),
        }),
        served_revision: Some(1),
        harness: None,
    };

    struct BridgeFixtureMaterial {
        material: crate::host_tools::operations::RevisionMaterial,
    }

    impl RevisionMaterialSource for BridgeFixtureMaterial {
        fn material_at(
            &self,
            revision: u64,
        ) -> Result<crate::host_tools::operations::RevisionMaterial, String> {
            if revision == 1 {
                return Ok(self.material.clone());
            }
            Err(format!(
                "bridge launch fixture serves only revision 1 (asked {revision})"
            ))
        }

        fn resolve_legacy(&self, _token: &odin_domain::SeatToken) -> Result<u64, String> {
            Err("bridge launch fixture resolves no legacy generation".to_owned())
        }
    }
    Composition {
        factory,
        live,
        manifest,
        _dirs: dirs,
    }
}

#[tokio::test]
async fn remote_workload_reclaim_without_home_continues_remote_context() {
    let composition = compose_fixture(&[], None, None, (true, true), false, false, None);
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    let (fresh, _, _) = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .expect("fresh remote workload");
    let (reclaimed, _, _) = composition
        .factory
        .build(&composition.manifest, true)
        .await
        .expect("remote reclaim must not inspect host HOME");
    assert!(reclaimed.transport.is_some());
    assert_eq!(env_value(&reclaimed.process, "HOME"), None);
    assert_eq!(
        env_value(&reclaimed.process, "PI_CODING_AGENT_DIR"),
        Some("/state/.omp-agent/fixture-operation")
    );
    assert_ne!(fresh.process.cwd, reclaimed.process.cwd);
    assert!(!fresh
        .process
        .explicit_args
        .iter()
        .any(|arg| arg == "--continue"));
    assert!(reclaimed
        .process
        .launch_args()
        .any(|arg| arg == "--continue"));
    let args: Vec<_> = reclaimed.process.launch_args().collect();
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .expect("pod exec separator");
    assert!(args[separator + 1..].iter().any(|arg| arg == "--continue"));
    assert!(!args[..separator].iter().any(|arg| arg == "--continue"));
    assert!(!reclaimed
        .process
        .explicit_args
        .iter()
        .any(|arg| arg == "--resume"));
}

/// The declared launch identity plus the system-prompt flag the session
/// composed and the guidance file it names, so a test can prove which
/// prompt route (whole-prompt replacement vs append) the seat took.
fn declared_launch_args(
    args: &[String],
) -> (String, String, String, Option<String>, Option<String>) {
    let value_after = |flag: &str| {
        args.iter()
            .position(|argument| argument == flag)
            .map(|position| args[position + 1].clone())
    };
    let prompt_flag = ["--system-prompt", "--append-system-prompt"]
        .into_iter()
        .find(|flag| args.iter().any(|argument| argument == flag));
    let guidance = prompt_flag.and_then(value_after).map(|path| {
        std::fs::read_to_string(&path).expect("the seat system prompt is a readable file")
    });
    (
        value_after("--provider").expect("--provider rides the launch"),
        value_after("--model").expect("--model rides the launch"),
        value_after("--models").expect("--models rides the launch"),
        guidance,
        prompt_flag.map(|flag| flag.to_owned()),
    )
}

#[tokio::test]
async fn a_conversation_seats_guidance_is_the_whole_system_prompt() {
    let composition = compose(&[declared_seat(SEAT, true)], None);
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    let (fresh, _, _) = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .expect("fresh launch composes");
    let (provider, model, models, guidance, flag) =
        declared_launch_args(&fresh.process.explicit_args);
    assert_eq!(provider, PROVIDER);
    assert_eq!(model, MODEL);
    assert_eq!(models, format!("{PROVIDER}/{MODEL}"));
    assert_eq!(
        flag.as_deref(),
        Some("--system-prompt"),
        "a seat that declared [conversation] guidance replaces the harness's \
         default coding-assistant prompt with it instead of appending"
    );
    assert_eq!(
        guidance,
        Some(GUIDANCE.to_owned()),
        "declared guidance must reach the launch arguments verbatim"
    );
    assert!(
        !fresh
            .process
            .explicit_args
            .iter()
            .any(|argument| argument == "--append-system-prompt"),
        "the replacement route must not also carry the append route"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let prompt = fresh.process.cwd.join(crate::process::SYSTEM_PROMPT_FILE);
        let mode = std::fs::metadata(&prompt)
            .expect("prompt file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the seat system prompt is owner-only");
    }

    // The reclaim of the SAME durable session composes byte-identical
    // declared launch arguments: recovery never re-derives the model
    // from any declaration iteration order.
    let (recovered, _, _) = composition
        .factory
        .build(&composition.manifest, true)
        .await
        .expect("reclaim composes");
    let recovered_args = declared_launch_args(&recovered.process.explicit_args);
    assert_eq!(
        recovered_args,
        (provider, model, models, guidance, flag),
        "the recovered incarnation must launch the exact declared composition"
    );
}

/// A base process argument may not carry a prompt of its own: the declared guidance is the only one.
#[tokio::test]
async fn the_base_process_arguments_may_not_smuggle_a_prompt() {
    for flag in ["--append-system-prompt", "--system-prompt"] {
        let composition = compose(&[declared_seat(SEAT, true)], Some(flag));
        composition
            .live
            .create_session(composition.manifest.clone())
            .await
            .expect("session row");
        let error = composition
            .factory
            .build(&composition.manifest, false)
            .await
            .err()
            .expect("an undeclared base prompt is a composition failure");
        assert!(
            matches!(error, LiveError::InvalidRequest { .. }),
            "{flag}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_workload_profile_without_a_composed_law_refuses_the_launch_typed() {
    let composition = compose_with(&[declared_seat(SEAT, true)], None, true);
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    let error = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .err()
        .expect("an uncomposed workload law refuses the launch");
    match error {
        LiveError::InvalidRequest { message, .. } => assert!(
            message.contains(WORKLOAD_PROFILE),
            "the typed refusal must name the uncomposed profile: {message}"
        ),
        other => panic!("expected a typed invalid-request refusal, got: {other:?}"),
    }
}

/// One real resolved brain policy for the fixture seat: a declared slice
/// context policy narrowed against the declared serving model window. The
/// policy digest is genuine (resolved through the real path), so the
/// factory's BrainService open verifies it exactly like production.
/// `tokenizer` is the declared context counter identity the lane stages.
fn resolved_brain_policy(
    model: &str,
    window: u32,
    reserve: u32,
    tokenizer: &str,
) -> odin_brain::config::EffectiveBrainPolicy {
    resolved_policy(model, window, reserve, tokenizer, false)
}

fn resolved_policy(
    model: &str,
    window: u32,
    reserve: u32,
    tokenizer: &str,
    knowledge: bool,
) -> odin_brain::config::EffectiveBrainPolicy {
    use std::num::NonZeroU32;

    fn nz32(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("nonzero fixture")
    }
    let (slice_knowledge, seat_knowledge) = match knowledge {
        true => (
            format!(
                r#"knowledge = {{ required = false, atlas_sources = ["{BRAIN_SOURCE}"], retrieval_mode = "lexical", candidate_limit = 16, top_k = 8, min_score_micros = 1, chunk_tokens = 512, chunk_overlap_tokens = 64, embedding_backend = "disabled" }}"#
            ),
            format!(
                r#"brain_scope = ["{BRAIN_SOURCE}"]
knowledge = {{ atlas_sources = ["{BRAIN_SOURCE}"], required_tags = [], denied_tags = [], top_k = 8 }}"#
            ),
        ),
        false => (String::new(), "brain_scope = []".to_owned()),
    };
    let slice_source = format!(
        r#"
schema = "odin.registry.v1"
kind = "slice"
enabled = true
description = "context budget fixture slice"
capabilities = []
variables = {{}}
redirects = {{ out_of_scope = "NeedsPlan" }}
context = {{ max_bundle_tokens = 6144, reserve_output_tokens = {reserve}, control_tokens = 256, history_tokens = 2048, core_tokens = 1024, prefetch_tokens = 512, tool_result_tokens = 1024, tool_schema_tokens = 512, max_item_tokens = 512 }}
{slice_knowledge}
"#
    );
    let seat_source = format!(
        r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "context budget fixture seat"
categories = []
tool_refs = []
project_scope = []
{seat_knowledge}
limits = {{ max_parallel_runs = 2, max_sessions = 4, budget = {{ usd_micros = 1000000, window = {{ duration_seconds = 2592000 }} }} }}
context = {{ max_bundle_tokens = 24576, profile = "fixture" }}
"#
    );
    let slice: odin_registry::schema::SliceToml =
        toml::from_str(&slice_source).expect("fixture slice parses");
    let seat: odin_registry::schema::SeatToml =
        toml::from_str(&seat_source).expect("fixture seat parses");
    let model = odin_domain::knowledge::retrieval::ModelDescriptor {
        name: ModelName::new(model).expect("model name"),
        tokenizer: odin_domain::knowledge::ids::TokenizerId::new(tokenizer)
            .expect("fixture tokenizer id"),
        context_window_tokens: nz32(window),
    };
    odin_brain::config::EffectiveBrainPolicy::resolve(
        1,
        &slice,
        &seat,
        &BTreeMap::new(),
        &std::collections::BTreeMap::from([(
            "fixture",
            &odin_registry::ContextProfileToml::sized(
                std::num::NonZeroU32::new(2048).unwrap(),
                std::num::NonZeroU32::new(6144).unwrap(),
            ),
        )]),
        &model,
    )
    .expect("the fixture brain policy resolves")
}

fn env_value<'a>(spec: &'a OmpProcessSpec, name: &str) -> Option<&'a str> {
    spec.explicit_env
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn declared_context_budget_reaches_the_launch_environment_for_the_admitted_model() {
    let composition = compose_inner(
        &[],
        None,
        Some(resolved_brain_policy(
            MODEL,
            8192,
            1024,
            "odin.tokenizer.utf8-bytes.v1",
        )),
        false,
        false,
        None,
    );
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    // Stage every declared model's budget so model switching retains the matching guard.
    let expected = format!(
        "{PROVIDER}|{MODEL}|8192|1024|odin.tokenizer.utf8-bytes.v1;\
         {PROVIDER}|{SWITCH_MODEL}|20000|1024|odin.tokenizer.utf8-bytes.v1"
    );
    let (fresh, _, _) = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .expect("fresh launch composes");
    assert_eq!(
        env_value(&fresh.process, "ODIN_CONTEXT_BUDGET"),
        Some(expected.as_str()),
        "the declared window, effective reserve, declared counter identity, and the \
         exact admitted launch identity must reach the pinned child's environment"
    );

    // The reclaim of the SAME durable session re-stages the exact same
    // declaration: recovery never re-derives the budget from a different
    // source.
    let (recovered, _, _) = composition
        .factory
        .build(&composition.manifest, true)
        .await
        .expect("reclaim composes");
    assert_eq!(
        env_value(&recovered.process, "ODIN_CONTEXT_BUDGET"),
        Some(expected.as_str()),
        "the recovered incarnation must carry the identical declared budget"
    );
}

/// A declared NATIVE counting lane stages its exact counter identity: the
/// extension must know which pinned tokenizer family the whole-request
/// guard counts with, and the host verifies the live harness resolves the
/// same family before trusting any snapshot.
#[tokio::test]
async fn a_native_declared_lane_stages_its_exact_tokenizer_identity() {
    let composition = compose_inner(
        &[],
        None,
        Some(resolved_brain_policy(
            MODEL,
            8192,
            1024,
            "odin.tokenizer.qwen3.v1",
        )),
        false,
        false,
        None,
    );
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    let (fresh, _, _) = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .expect("fresh launch composes");
    assert_eq!(
        env_value(&fresh.process, "ODIN_CONTEXT_BUDGET"),
        Some(
            format!(
                "{PROVIDER}|{MODEL}|8192|1024|odin.tokenizer.qwen3.v1;\
                 {PROVIDER}|{SWITCH_MODEL}|20000|1024|odin.tokenizer.utf8-bytes.v1"
            )
            .as_str()
        ),
        "the native lane stages the exact declared counter identity"
    );
}

/// The seat shell works in the session's capsule, never in the declared
/// project root, and its HOME is the bubble's own /tmp: each command runs
/// through the wrapper and argv file the launch wrote, with the real bwrap.
#[tokio::test]
async fn the_seat_shell_writes_its_capsule_and_never_the_project_root() {
    let composition = compose_fixture(
        &[declared_seat(SEAT, true)],
        None,
        None,
        (false, false),
        false,
        true,
        None,
    );
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    let (fresh, _, _) = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .expect("sandboxed launch composes");
    let root = composition._dirs[3].path().join("project");
    let capsule = composition._dirs[3].path().join("capsule");
    let host = host_sandbox();
    let wrapper = fresh.process.cwd.join("host-shell");
    std::fs::write(
        &wrapper,
        crate::process::shell_wrapper_script(
            &host.bwrap,
            &fresh.process.cwd.join("shell.argv"),
            &host.bash,
        )
        .expect("wrapper"),
    )
    .expect("write wrapper");
    let output = std::process::Command::new(&host.bash)
        .arg(&wrapper)
        .args([
            "-c",
            "pwd; echo \"$HOME\"; touch wtest \"$HOME/wtest\"; mkdir -p \"$HOME/.cache/nix\"",
        ])
        .output()
        .expect("the shell bubble runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [capsule.to_str().expect("utf-8"), "/tmp"]
    );
    assert!(capsule.join("wtest").is_file());
    assert!(!capsule.join(".cache").exists());
    assert_eq!(
        std::fs::read_dir(&root).expect("project root").count(),
        0,
        "the shell wrote into the declared project root"
    );
}

/// A declared project sphere is the lane's whole filesystem: the capsule
/// and the sphere's own scratch are writable, its data roots read-only, the
/// seat's sandbox role paths are gone, and `/dev` is absent because no
/// device is attached.
#[tokio::test]
async fn a_declared_sphere_replaces_the_seat_roles_and_binds_only_its_roots() {
    let sphere_root = tempfile::tempdir().expect("sphere root");
    let data = sphere_root.path().join("data");
    let scratch = sphere_root.path().join("scratch");
    std::fs::create_dir_all(&data).expect("data root");
    std::fs::write(data.join("notes.txt"), "run outputs are read-only\n").expect("data file");
    std::fs::create_dir_all(&scratch).expect("scratch root");
    let sphere = crate::process::SphereProjection {
        data_roots: vec![data.clone()],
        scratch: scratch.clone(),
        devices: Vec::new(),
        endpoints: Vec::new(),
    };
    let composition = compose_fixture(
        &[declared_seat(SEAT, true)],
        None,
        None,
        (false, false),
        false,
        true,
        Some(sphere),
    );
    composition
        .live
        .create_session(composition.manifest.clone())
        .await
        .expect("session row");
    let (fresh, _, _) = composition
        .factory
        .build(&composition.manifest, false)
        .await
        .expect("sphere launch composes");
    let capsule = composition._dirs[3].path().join("capsule");
    let host = host_sandbox();
    let wrapper = fresh.process.cwd.join("host-shell");
    std::fs::write(
        &wrapper,
        crate::process::shell_wrapper_script(
            &host.bwrap,
            &fresh.process.cwd.join("shell.argv"),
            &host.bash,
        )
        .expect("wrapper"),
    )
    .expect("write wrapper");
    let seat_scratch = fresh.process.cwd.join("scratch");
    let notes = data.join("notes.txt");
    let script = format!(
        "pwd; cat {notes}; \
         (echo broken > {notes}) 2>/dev/null && echo DATA-WROTE || echo DATA-READONLY; \
         touch {scratch}/wtest && echo SCRATCH-OK; \
         test -d {seat_scratch} && echo SEAT-SCRATCH || echo NO-SEAT-SCRATCH; \
         test -e /dev && echo HAS-DEV || echo NO-DEV",
        notes = notes.display(),
        scratch = scratch.display(),
        seat_scratch = seat_scratch.display(),
    );
    let output = std::process::Command::new(&host.bash)
        .arg(&wrapper)
        .args(["-c", &script])
        .output()
        .expect("the sphere shell bubble runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            capsule.to_str().expect("utf-8"),
            "run outputs are read-only",
            "DATA-READONLY",
            "SCRATCH-OK",
            "NO-SEAT-SCRATCH",
            "NO-DEV",
        ],
        "the sphere is the whole filesystem the shell sees"
    );
    assert!(scratch.join("wtest").is_file());
    assert_eq!(
        std::fs::read_to_string(&notes).expect("data file intact"),
        "run outputs are read-only\n",
        "a data root is read-only"
    );
}
