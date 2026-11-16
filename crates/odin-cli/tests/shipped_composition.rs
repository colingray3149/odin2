//! The shipped registry's enabled capabilities resolve against the daemon's
//! compiled handler surface: the same HostToolRegistry composition odind
//! builds at startup, run through the exact `from_contracts` admission that
//! refuses daemon start when a binding goes missing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use odin_cli::runtime_bindings::{operation_contracts, OPERATOR_CAPABILITY_BINDINGS};
use odin_domain::CapabilityId;
use odin_hermes::config::HermesSettings;
use odin_hermes::runtime::{
    hermes_capability_bindings, hermes_host_tools, HermesLedgers, HermesRuntime,
};
use odin_huginn::{OdindConfig, OdindModelCost, OdindModelLaneConfig};
use odin_ledger::Ledger;
use odin_omp::host_tools::operations::{admission_digest, DeclaredOperationCatalog};
use odin_omp::host_tools::{
    adapter::register_adapter_markers, brain, delegation::TaskOwnerSlot, device, kube, pod_exec,
    workflow, BrowserCapabilityOwnerSlot, CanonicalV2CapabilityBinding, CanonicalV2CapabilityOwner,
    HostInvocation, HostToolError, HostToolRegistry, InternalBindingKey, ModelVisibleToolConfig,
};
use odin_registry::{parse_objects, walk};
use serde_json::{json, Value};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::{commit_all, git};

/// The daemon binds capsule authority over the live session pool; the
/// composition under test is which bindings register, not owner behavior.
struct CapsuleOwner;
impl CanonicalV2CapabilityOwner for CapsuleOwner {
    fn invoke_authority_binding(
        &self,
        _binding: CanonicalV2CapabilityBinding,
        _capsule_id: odin_types::CapsuleId,
        _correlation_id: odin_types::CorrelationId,
        _invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        Ok(json!({ "ok": true }))
    }
    fn preflight_authority_binding(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _binding: CanonicalV2CapabilityBinding,
        _scope: &odin_domain::Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }
}

/// The composition under test registers pod-exec tools; no pod runs here.
struct NoPods;
impl pod_exec::PodWorkerExec for NoPods {
    fn exec(
        &self,
        _run: &odin_domain::RunId,
        _argv: &[String],
        _stdin: Option<&[u8]>,
        _wait: std::time::Duration,
        _tail_bytes: usize,
    ) -> Result<pod_exec::WorkerOutput, pod_exec::WorkerExecFault> {
        Err(pod_exec::WorkerExecFault::NotStarted(
            "no pods in this test".to_owned(),
        ))
    }
}

/// The daemon's host-tool composition over the shipped registry, in startup
/// assembly order: the model-visible builtins, brain, the hermes surfaces and
/// internal bindings, task/context owners, the three live-coordinator owners,
/// and the declared-adapter markers. The directories back the composed state.
struct Composition {
    contracts: BTreeMap<CapabilityId, odin_kernel::CapabilityContract>,
    registry: HostToolRegistry,
    _dirs: [tempfile::TempDir; 3],
}

/// The shipped registry published as odind pins it: `registry/` and
/// `schemas/` committed in a scratch repository, then validated.
fn shipped_snapshot(root: &Path, scratch: &Path) -> Arc<odin_registry::SnapshotHandle> {
    let repository = scratch.join("registry-fixture");
    std::fs::create_dir_all(&repository).expect("fixture repository");
    for tree in ["registry", "schemas"] {
        let status = std::process::Command::new("cp")
            .args(["-r"])
            .arg(root.join(tree))
            .arg(&repository)
            .status()
            .expect("cp runs");
        assert!(status.success(), "copy {tree}");
    }
    git(&repository, &["init", "--quiet"]);
    let head = commit_all(&repository, "shipped registry");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &repository,
        &head,
        odin_cli::runtime_bindings::admitted_registry_bindings(),
    )
    .expect("shipped registry validates");
    let store = odin_registry::SnapshotStore::new(scratch.join("snapshot.json"));
    store.publish_committed(&candidate, 1).expect("publish");
    Arc::new(odin_registry::SnapshotHandle::open(store).expect("snapshot opens"))
}

fn daemon_composition() -> Composition {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let discovery = walk(root.join("registry"));
    let parsed = parse_objects(&discovery.objects);
    // Production refuses Fail findings. A parse error omits the object, so
    // composition must not pass against the remainder. Flag is advice.
    let mut failures: Vec<_> = discovery
        .findings
        .iter()
        .chain(&parsed.findings)
        .filter(|finding| finding.is_failure())
        .collect();
    failures.sort();
    assert!(
        failures.is_empty(),
        "{} shipped registry Fail finding(s):\n{}",
        failures.len(),
        failures
            .iter()
            .map(|finding| {
                format!(
                    "{} {}: {}",
                    finding.code,
                    finding.path.display(),
                    finding.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    );
    let contracts =
        operation_contracts(&parsed.objects).expect("shipped registry derives contracts");
    assert!(
        !contracts.is_empty(),
        "the shipped registry declares capabilities"
    );

    // The hermes runtime carries the same admitted contracts the daemon
    // opens with, so `hermes_capability_bindings` publishes the exact
    // handler/extractor owners startup registers.
    let state = tempfile::tempdir().expect("hermes state directory");
    let hermes = Arc::new(
        HermesRuntime::open(
            HermesSettings::new(
                state.path().join("state"),
                None,
                None,
                Vec::new(),
            )
            .expect("hermes settings"),
            HermesLedgers {
                conversation: Ledger::open_in_memory().expect("conversation ledger"),
                adapter: Arc::new(parking_lot::Mutex::new(
                    Ledger::open_in_memory().expect("adapter ledger"),
                )),
                purchase: Arc::new(Mutex::new(
                    Ledger::open_in_memory().expect("purchase ledger"),
                )),
            },
            &contracts,
            None,
            8_192,
            BTreeMap::new(),
            None,
        )
        .expect("hermes runtime opens"),
    );

    let scratch = tempfile::tempdir().expect("registry scratch directory");
    for directory in ["crates/demo/src", "extension", "registry", "skeletons"] {
        std::fs::create_dir_all(scratch.path().join(directory)).expect("atlas fixture directory");
    }
    std::fs::write(
        scratch.path().join("crates/demo/src/lib.rs"),
        "pub fn stable(value: u64) -> u64 { value }\n",
    )
    .expect("atlas fixture source");
    let mut registry = HostToolRegistry::model_visible(ModelVisibleToolConfig {
        ledger: Arc::new(Mutex::new(Ledger::open_in_memory().expect("bridge ledger"))),
        atlas: Arc::new(std::sync::OnceLock::from(Arc::new(
            odin_atlas::build(odin_atlas::AtlasSources::new(scratch.path()))
                .expect("atlas composes"),
        ))),
        allowed_atlas_scope: odin_atlas::AtlasScope::default(),
    })
    .expect("model-visible builtins assemble");
    brain::register(
        &mut registry,
        Arc::new(std::sync::OnceLock::new()),
        &contracts,
    )
    .expect("brain tools register");
    for tool in hermes_host_tools(&hermes) {
        registry.register(tool).expect("hermes surface registers");
    }
    for (id, tool) in hermes_capability_bindings(&hermes) {
        registry
            .register_internal(InternalBindingKey::Builtin(id.to_owned()), tool)
            .expect("hermes capability binding registers");
    }
    registry
        .register_task_capabilities(Arc::new(TaskOwnerSlot::new()))
        .expect("task capabilities register");
    registry
        .register_context_read(scratch.path(), 4_096)
        .expect("context read registers");
    registry
        .register_browser_capabilities(Arc::new(BrowserCapabilityOwnerSlot::new()))
        .expect("browser capabilities register");
    registry
        .register_canonical_v2_capabilities(Arc::new(CapsuleOwner))
        .expect("canonical-v2 capabilities register");
    registry
        .register_kube_capabilities(Arc::new(kube::KubeCapabilityOwnerSlot::new()))
        .expect("kube capabilities register");
    register_adapter_markers(&mut registry).expect("adapter markers register");
    pod_exec::register(
        &mut registry,
        pod_exec::PodExecBinding {
            specs: odin_cli::runtime_bindings::pod_exec_specs(&parsed.objects),
            pods: Arc::default(),
            exec: Arc::new(NoPods),
            web_save: None,
            research: None,
            host_recon: None,
        },
        &contracts,
        &odin_omp::host_tools::operations::FilesystemSchemaCatalog::new(&root),
    )
    .expect("pod-exec tools register");
    workflow::register(
        &mut registry,
        workflow::WorkflowBinding { runner: None },
        &contracts,
        &odin_omp::host_tools::operations::FilesystemSchemaCatalog::new(&root),
    )
    .expect("workflow tools register");
    let device_state = tempfile::tempdir().expect("device state directory");
    device::register(
        &mut registry,
        device::DeviceRunBinding {
            registry: shipped_snapshot(&root, device_state.path()),
            state_root: device_state.path().to_path_buf(),
            run: Arc::new(|_, _, _, _| Err("composition test runs no device".to_owned())),
            tool_path: Vec::new(),
            executables: BTreeMap::new(),
        },
        &contracts,
        &odin_omp::host_tools::operations::FilesystemSchemaCatalog::new(&root),
    )
    .expect("device tools register");
    Composition {
        contracts,
        registry,
        _dirs: [state, scratch, device_state],
    }
}

#[test]
fn shipped_registry_capabilities_resolve_in_the_daemon_composition() {
    let Composition {
        contracts,
        registry,
        ..
    } = daemon_composition();
    // The exact startup admission: every non-operator capability's handler
    let digest = admission_digest(&contracts, 1).expect("admission digest");
    let operator_owned: BTreeSet<CapabilityId> = OPERATOR_CAPABILITY_BINDINGS
        .iter()
        .map(|binding| CapabilityId::new(binding.capability).expect("operator capability id"))
        .collect();
    DeclaredOperationCatalog::from_contracts(
        &contracts,
        1,
        digest,
        Arc::new(registry),
        &operator_owned,
    )
    .expect("every daemon-bound capability of the shipped registry resolves");
}
/// The enabled workflow capabilities of the shipped registry, by id.
fn shipped_workflows() -> BTreeMap<String, odin_registry::schema::CapabilityToml> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    parse_objects(&walk(root.join("registry")).objects)
        .objects
        .into_iter()
        .filter_map(|object| match object.config {
            odin_registry::ObjectConfig::Capability(capability)
                if capability.enabled && capability.is_workflow() =>
            {
                Some((object.id, *capability))
            }
            _ => None,
        })
        .collect()
}

fn compiled_workflows(dir: &Path) -> odin_workflows::Catalog {
    odin_workflows::Catalog::new(
        &odin_cli::runtime_bindings::workflow_families(),
        odin_workflows::testing::ctx_for(dir, &[], &[], &[], &[]),
    )
    .expect("the compiled workflow families list each capability once")
}

/// Registry and code never drift: every enabled workflow capability has a
/// compiled workflow, and every compiled workflow an enabled, marked capability.
#[test]
fn shipped_workflow_capabilities_are_compiled() {
    let declared = shipped_workflows();
    let dir = tempfile::tempdir().expect("ctx directory");
    let catalog = compiled_workflows(dir.path());
    let mut drift: Vec<String> = declared
        .keys()
        .filter(|id| !catalog.compiled(id))
        .map(|id| format!("workflow capability {id} has no compiled workflow; add it to its family's WORKFLOWS table"))
        .collect();
    drift.extend(catalog.ids().filter_map(|id| match declared.get(id) {
        Some(capability) if capability.binds_workflow_markers() => None,
        Some(_) => Some(format!("workflow capability {id} does not bind the workflow markers")),
        None => Some(format!(
            "compiled workflow {id} has no enabled workflow capability; add registry/capabilities/{id}/capability.toml"
        )),
    }));
    assert!(drift.is_empty(), "{drift:#?}");
}

#[test]
fn shipped_gateway_cards_pass_real_seat_model_validation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let parsed = parse_objects(&walk(root.join("registry")).objects);
    let mut config = OdindConfig::parse(&format!(
        "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'mini'\n[paths]\nregistry_root = '/'\nstate_root = '/'\nregistry_snapshot = '/'\nauthority_token_root = '/'\nauthority_verification_key_file = '/'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '{}'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_hub = 'hub.test'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:{}'\n[publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'f'\nrender_lane = 'r'\n[capacity]\n",
        "a".repeat(40),
        "c".repeat(64)
    ))
    .expect("minimal config");
    for object in &parsed.objects {
        let odin_registry::ObjectConfig::Model(card) = &object.config else {
            continue;
        };
        let Some(lane) = card.lane() else {
            continue;
        };
        config.models.lanes.insert(
            lane.to_owned(),
            OdindModelLaneConfig {
                seats: card.seats,
                strengths: card.strengths.clone(),
                tier: card.tier.clone(),
                display_name: card.description.clone(),
                context_window: card
                    .window
                    .as_ref()
                    .and_then(|window| window.context_tokens)
                    .unwrap_or(1),
                cost: OdindModelCost {
                    input: "0".to_owned(),
                    output: "0".to_owned(),
                },
                billing: "subscription".to_owned(),
            },
        );
    }
    config
        .adopt_projects_from(Path::new("/nonexistent"), &parsed.objects)
        .expect("the shipped seat model declarations resolve against bare lanes");
}
