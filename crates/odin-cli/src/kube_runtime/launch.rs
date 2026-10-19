//! Trusted-host identity derivation and published-profile launch
//! construction.

use std::collections::BTreeMap;

use crate::workload_park::PASSIVE_ARGV;
use crate::KubeLaunchBinding;
use odin_domain::huginn::{
    KubeContentIdentity, KubeJobLabels, KubeOperationKind, KubeResourceVersion,
    KubeStagingProjection,
};
use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
use odin_kernel::stop::{mint_worker_id, WorkerId};
use odin_kube::job::{JobExtensionLaunch, JobLaunch, JobModelsConfigLaunch};
use odin_omp::host_tools::HostToolError;
use odin_registry::schema::{ContainerToml, WorkloadProfileToml};
use odin_registry::ContainerIdentity;
use odin_types::OperationId;

use super::admission::arguments_error;

/// 32-hex-character deterministic identity material for derived ids.
fn digest16(seed: &str) -> String {
    let digest = Digest::hash(seed.as_bytes());
    digest
        .as_bytes()
        .iter()
        .rev()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Explicit initial placement binds the create operation without changing
/// historical scheduler-selected operation identities.
fn initial_placement_digest(mut seed: String, target: Option<&str>) -> Digest {
    if let Some(node) = target {
        seed.push_str(":initial-target:");
        seed.push_str(node);
    }
    Digest::hash(seed.as_bytes())
}

/// Derives the actuation kind and idempotency digest for one run-addressed
/// mutation from the admitted operation content only: verb, run, and the
/// exact opaque expectedResourceVersion the model supplied at admission.
/// Distinct resourceVersions are distinct durable operations (a stale CAS
/// rejection is journaled under its own operation), and identical retries
/// carry an identical digest, so the reconciler's journal replays them.
/// The operation id itself is the permit's, never derived here.
pub(super) fn mutation_operation(
    tool: &'static str,
    verb: &'static str,
    run_id: &RunId,
    expected_resource_version: &KubeResourceVersion,
    target_node: Option<&str>,
) -> Result<(KubeOperationKind, Digest), HostToolError> {
    let kind = match verb {
        "pause" => KubeOperationKind::Pause,
        "resume" => KubeOperationKind::Resume,
        "restart" => KubeOperationKind::Restart,
        "cancel" => KubeOperationKind::Cancel,
        other => {
            return Err(arguments_error(
                tool,
                format!("unsupported workload verb {other:?}"),
            ));
        }
    };
    let mut seed = format!(
        "kube:{verb}:{run_id}:{}",
        expected_resource_version.as_str()
    );
    // A rehome is a different operation from a plain restart.
    if let Some(node) = target_node {
        seed.push_str(&format!(":rehome:{node}"));
    }
    let idempotency_digest = Digest::hash(seed.as_bytes());
    Ok((kind, idempotency_digest))
}

/// The published profile's canonical identity: exactly the registry's
/// identity-bearing field records (base, contents kind, monitoring slice,
/// purpose, scripts), computed by the registry's own identity calculator.
pub(super) fn container_identity(
    tool: &'static str,
    container: &ContainerToml,
) -> Result<Digest, HostToolError> {
    ContainerIdentity::calculate(container)
        .map(|identity| identity.digest())
        .map_err(|error| arguments_error(tool, format!("profile identity rejected: {error}")))
}

/// Builds the trusted-host launch contract from the admitted published
/// profile: the OCI image is the identity-bearing `base`, the argv payload is
/// the identity-bearing `scripts` under the profile's fixed `/bin/sh -c`
/// executor, the profile's declared GPU reservation and wall-clock deadline
/// ride the launch verbatim, the worker incarnation is host-minted, and
/// staging carries no fabricated inputs (profile Jobs start from the image
/// alone).
#[allow(clippy::too_many_arguments)]
pub(super) fn profile_launch(
    tool: &'static str,
    container: &ContainerToml,
    identity: Digest,
    binding: &KubeLaunchBinding,
    run_id: RunId,
    project_id: ProjectId,
    lane_id: LaneId,
    seat_id: SeatId,
    attempt: Option<AttemptId>,
    operation_id: OperationId,
    initial_target_node: Option<String>,
) -> Result<JobLaunch, HostToolError> {
    if !container.image_executable_paths() {
        return Err(arguments_error(
            tool,
            "the published profile requires a versioned OCI image executable path profile",
        ));
    }
    if container.scripts.is_empty() {
        return Err(arguments_error(
            tool,
            "the published profile declares no scripts",
        ));
    }
    let worker_id: WorkerId = mint_worker_id()
        .map_err(|error| arguments_error(tool, format!("worker identity rejected: {error}")))?;
    let attempt_id = match attempt {
        Some(attempt_id) => attempt_id,
        None => AttemptId::new(format!(
            "kube-attempt-{}",
            digest16(&format!("attempt:{run_id}:{operation_id}"))
        ))
        .map_err(|error| arguments_error(tool, format!("attempt identity rejected: {error}")))?,
    };
    let task_id = TaskId::new(format!("kube-task-{}", digest16(&format!("task:{run_id}"))))
        .map_err(|error| arguments_error(tool, format!("task identity rejected: {error}")))?;
    let script = container
        .scripts
        .iter()
        .map(|script| {
            let path = format!("/{}", script.trim_start_matches('/'));
            format!("'{}'", path.replace('\'', "'\\''"))
        })
        .collect::<Vec<_>>()
        .join(" && ");
    Ok(JobLaunch {
        labels: KubeJobLabels {
            task_id,
            run_id: run_id.clone(),
            attempt_id,
            seat_id,
            project_id,
            lane_id,
            model: binding.model.clone(),
            budget_policy_digest: binding.budget_policy_digest,
            container_identity: identity,
        },
        worker_id,
        staging: KubeStagingProjection {
            inputs: Vec::new(),
            resumed_from: None,
        },
        checkpoint: None,
        image: container.base.clone(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec![script],
        node_selector: BTreeMap::new(),
        gpu_count: container.gpu_count,
        deadline_seconds: container.deadline_seconds,
        service: false,
        // Container-profile launches carry no workload pod binding; the
        // workload-profile dispatch owns building WorkloadPodPlan values.
        workload: None,
        extension: None,
        models_config: None,
        operation_id,
        idempotency_digest: initial_placement_digest(
            format!("create:{run_id}:{}", container.base),
            initial_target_node.as_deref(),
        ),
        initial_target_node,
    })
}

/// The pinned verifier runs as passive init, reaping children without launching
/// the agent. Only the host attach starts the RPC launcher after UID verification,
/// so startup frames cannot precede their consumer. Declared argv retains kubelet expansion.
#[allow(clippy::too_many_arguments)]
pub(super) fn workload_profile_launch(
    tool: &'static str,
    profile: &WorkloadProfileToml,
    plan: odin_kube::workload::WorkloadPodPlan,
    binding: &KubeLaunchBinding,
    run_id: RunId,
    project_id: ProjectId,
    lane_id: LaneId,
    seat_id: SeatId,
    attempt: Option<AttemptId>,
    operation_id: OperationId,
    model: String,
    extension: JobExtensionLaunch,
    policy_input: KubeContentIdentity,
    models_input: KubeContentIdentity,
    declared_inputs: Vec<KubeContentIdentity>,
    credential: odin_kube::workload::WorkloadCredentialEnv,
    initial_target_node: Option<String>,
) -> Result<JobLaunch, HostToolError> {
    let agent = profile.agent().ok_or_else(|| {
        arguments_error(
            tool,
            "the workload profile runs no agent harness".to_owned(),
        )
    })?;
    let worker_id: WorkerId = mint_worker_id()
        .map_err(|error| arguments_error(tool, format!("worker identity rejected: {error}")))?;
    let attempt_id = match attempt {
        Some(attempt_id) => attempt_id,
        None => AttemptId::new(format!(
            "workload-attempt-{}",
            digest16(&format!("attempt:{run_id}:{operation_id}"))
        ))
        .map_err(|error| arguments_error(tool, format!("attempt identity rejected: {error}")))?,
    };
    let task_id = TaskId::new(format!(
        "workload-task-{}",
        digest16(&format!("task:{run_id}"))
    ))
    .map_err(|error| arguments_error(tool, format!("task identity rejected: {error}")))?;
    let budget = binding.budget_policy_digest;
    // The carrier pod's init argv: the admitted verifier path — the image
    // identity's own declared odind entrypoint — in its mechanism-only
    // passive mode. Hoisted above the launch literal because the extension
    // binding moves into it.
    let command = vec![extension.verifier.clone()];
    let args = vec![PASSIVE_ARGV.to_owned()];
    // Hoisted above the launch literal: the staging inputs move
    // `models_input` into the projection, so the document binding must
    // borrow its fields first.
    let models_launch = JobModelsConfigLaunch {
        config_artifact: models_input.artifact_id.clone(),
        config_digest: models_input.content_digest.to_string(),
        credential_env: credential.env_name,
    };
    Ok(JobLaunch {
        labels: KubeJobLabels {
            task_id,
            run_id: run_id.clone(),
            attempt_id,
            seat_id,
            project_id,
            lane_id,
            model,
            budget_policy_digest: budget,
            container_identity: Digest::hash(
                format!(
                    "workload:{}:{}",
                    profile.image.reference, agent.runtime.launcher
                )
                .as_bytes(),
            ),
        },
        worker_id,
        staging: KubeStagingProjection {
            // input-0 carries the extension policy, input-1 the models
            // document: the in-pod verifier consumes both by this exact
            // journaled order. Declared launch inputs follow from input-2
            // (super::execution::agent_input_bindings names their paths).
            inputs: [policy_input, models_input]
                .into_iter()
                .chain(declared_inputs)
                .collect(),
            resumed_from: None,
        },
        checkpoint: None,
        workload: Some(plan),
        extension: Some(extension),
        models_config: Some(models_launch),
        image: profile.image.reference.clone(),
        command,
        args,
        // Declared placement: the node labels of the declared host
        // capabilities; scheduler admission still decides among them.
        node_selector: profile.placement_labels(),
        gpu_count: profile.gpu_count,
        // A job's declared lifetime is its hard wall clock; a service has none.
        deadline_seconds: profile.deadline_seconds(),
        service: false,
        operation_id,
        idempotency_digest: initial_placement_digest(
            format!("workload-create:{run_id}:{}", profile.image.reference),
            initial_target_node.as_deref(),
        ),
        initial_target_node,
    })
}

/// Script pods use the declared image, argv, resources, and lifecycle without
/// an agent, gateway, extension, or session.
#[allow(clippy::too_many_arguments)]
pub(super) fn script_profile_launch(
    tool: &'static str,
    inputs: &crate::kube_runtime::ScriptLaunchInputs,
    staged_inputs: Vec<odin_domain::huginn::KubeContentIdentity>,
    binding: &KubeLaunchBinding,
    run_id: RunId,
    attempt: Option<AttemptId>,
    operation_id: OperationId,
    initial_target_node: Option<String>,
) -> Result<JobLaunch, HostToolError> {
    let profile = &inputs.profile.profile;
    let command = profile
        .script
        .as_ref()
        .map(|script| script.command.clone())
        .filter(|command| !command.is_empty())
        .ok_or_else(|| {
            arguments_error(
                tool,
                format!("script pod {} declares no command", inputs.profile.id),
            )
        })?;
    let worker_id: WorkerId = mint_worker_id()
        .map_err(|error| arguments_error(tool, format!("worker identity rejected: {error}")))?;
    let attempt_id = match attempt {
        Some(attempt_id) => attempt_id,
        None => AttemptId::new(format!(
            "workload-attempt-{}",
            digest16(&format!("attempt:{run_id}:{operation_id}"))
        ))
        .map_err(|error| arguments_error(tool, format!("attempt identity rejected: {error}")))?,
    };
    let task_id = TaskId::new(format!(
        "workload-task-{}",
        digest16(&format!("task:{run_id}"))
    ))
    .map_err(|error| arguments_error(tool, format!("task identity rejected: {error}")))?;
    let plan = odin_kube::workload::WorkloadPodPlan {
        profile: inputs.profile.id.clone(),
        state_mount: profile.state.path.clone(),
        export_mount: profile.export.pod_path.clone(),
        export_host_folder: profile.export.host_folder.clone(),
        state_storage: profile.state.storage.clone(),
        state_storage_class: None,
        allow_hosts: profile.network.allow_hosts.clone(),
        agent: None,
    };
    plan.validate()
        .map_err(|reason| arguments_error(tool, format!("script pod plan rejected: {reason}")))?;
    let identity = Digest::hash(
        format!(
            "workload-script:{}:{}",
            profile.image.reference,
            command.join("\u{1f}")
        )
        .as_bytes(),
    );
    let (program, args) = command.split_first().expect("the command is nonempty");
    Ok(JobLaunch {
        labels: KubeJobLabels {
            task_id,
            run_id: run_id.clone(),
            attempt_id,
            seat_id: inputs.seat.clone(),
            project_id: inputs.project.clone(),
            lane_id: inputs.lane.clone(),
            model: binding.model.clone(),
            budget_policy_digest: binding.budget_policy_digest,
            container_identity: identity,
        },
        worker_id,
        staging: KubeStagingProjection {
            inputs: staged_inputs,
            resumed_from: None,
        },
        checkpoint: None,
        image: profile.image.reference.clone(),
        command: vec![program.clone()],
        args: args.to_vec(),
        node_selector: profile.placement_labels(),
        gpu_count: profile.gpu_count,
        deadline_seconds: profile.deadline_seconds(),
        service: profile.mode == odin_registry::WorkloadMode::Service,
        workload: Some(plan),
        extension: None,
        models_config: None,
        operation_id,
        idempotency_digest: initial_placement_digest(
            format!("script-create:{run_id}:{}", profile.image.reference),
            initial_target_node.as_deref(),
        ),
        initial_target_node,
    })
}

#[cfg(test)]
mod profile_launch_tests {
    use super::*;

    fn gpu_smoke_profile() -> ContainerToml {
        toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Bounded one-GPU smoke fixture."
purpose = "gpu-smoke"
base = "nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0-ubuntu22.04"
seats_offered = ["kubert"]
scripts = ["cuda-samples/sample"]
watchdogs = []
identity_fields = ["base", "gpu_count", "deadline_seconds", "purpose", "scripts"]
tunables = {}
surface = []
gpu_count = 1
deadline_seconds = 300
contents = { kind = "scripts" }
monitoring = "none"
"#,
        )
        .expect("gpu smoke fixture profile")
    }

    #[test]
    fn the_profile_reservation_and_deadline_ride_the_launch_verbatim() {
        let binding = KubeLaunchBinding {
            model: "kubert-mini".to_owned(),
            budget_policy_digest: Digest::hash(b"profile-launch-budget"),
        };
        for target in [None, Some("mini"), Some("other-node")] {
            let launch = profile_launch(
                "kube_workload_create",
                &gpu_smoke_profile(),
                Digest::hash(b"fixture-identity"),
                &binding,
                RunId::new("run:live:profile-launch").expect("run id"),
                ProjectId::new("odin").expect("project id"),
                LaneId::new("kubert-odin").expect("lane id"),
                SeatId::new("kubert").expect("seat id"),
                None,
                OperationId::new("op-profile-launch").expect("operation id"),
                target.map(str::to_owned),
            )
            .expect("the admitted profile builds a launch");
            assert_eq!(launch.initial_target_node.as_deref(), target);
            let seed = format!(
                "create:{}:{}",
                launch.labels.run_id,
                gpu_smoke_profile().base
            );
            let historical = Digest::hash(seed.as_bytes());
            match target {
                None => assert_eq!(launch.idempotency_digest, historical),
                Some(node) => {
                    assert_ne!(launch.idempotency_digest, historical);
                    assert_eq!(
                        launch.idempotency_digest,
                        Digest::hash(format!("{seed}:initial-target:{node}").as_bytes())
                    );
                }
            }
            assert_eq!(
                launch.gpu_count, 1,
                "the declared GPU reservation rides verbatim"
            );
            assert_eq!(
                launch.deadline_seconds,
                Some(300),
                "the declared deadline rides verbatim"
            );
            assert_eq!(
                launch.args,
                vec!["'/cuda-samples/sample'".to_owned()],
                "the image-internal executable stays the quoted-path argv law"
            );
            assert!(
                launch.node_selector.is_empty(),
                "a GPU reservation is placement input, never a node pin"
            );
        }
    }

    #[test]
    fn the_workload_lifetime_rides_the_launch_as_its_deadline() {
        let profile: WorkloadProfileToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Lifetime regression profile."

[image]
reference = "localhost/odin-fixture@sha256:1111111111111111111111111111111111111111111111111111111111111111"

[runtime]
launcher = "/odin/bin/omp"
browser = "/odin/bin/chromium"
supervisor = "/odin/bin/odind"
playwright = "/odin/lib/playwright-core"

[seat]
seat = "kubert"
project = "odin"
gateway_lane = "kubert-odin"

[network]
allow_hosts = ["arxiv.org"]

[display]
xvfb = "/odin/bin/Xvfb"
screen = "1280x800x24"
stream = true

[state]
path = "/state"
storage = "2Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/export"

[brief]
text = "Read the declared papers."

[memory]
namespace = "atlas.code"

[lifetime]
deadline_seconds = 5400
"#,
        )
        .expect("workload fixture profile");
        for target in [None, Some("mini"), Some("other-node")] {
            let credential = odin_kube::workload::WorkloadCredentialEnv {
                env_name: "ODIN_GATEWAY_KEY".into(),
                secret: "gateway-secret".into(),
                key: "master".into(),
            };
            let plan = odin_kube::workload::WorkloadPodPlan {
                profile: "lifetime-fixture".to_owned(),
                state_mount: profile.state.path.clone(),
                export_mount: profile.export.pod_path.clone(),
                export_host_folder: profile.export.host_folder.clone(),
                state_storage: profile.state.storage.clone(),
                state_storage_class: None,
                allow_hosts: profile.network.allow_hosts.clone(),
                agent: Some(odin_kube::workload::WorkloadAgentPlan {
                    launcher: profile.runtime.as_ref().unwrap().launcher.clone(),
                    gateway: odin_kube::workload::WorkloadGatewayTarget {
                        host: "gateway.example.net".to_owned(),
                        port: 4000,
                    },
                    browser: profile.runtime.as_ref().unwrap().browser.clone(),
                    supervisor: profile.runtime.as_ref().unwrap().supervisor.clone(),
                    playwright: profile.runtime.as_ref().unwrap().playwright.clone(),
                    browser_node: "/odin/bin/node".to_owned(),
                    browser_engine: odin_registry::BrowserEngine::default(),
                    display: odin_kube::workload::WorkloadDisplayPlan {
                        xvfb: profile.display.as_ref().unwrap().xvfb.clone(),
                        screen: profile.display.as_ref().unwrap().screen.clone(),
                        stream: profile.display.as_ref().unwrap().stream,
                    },
                    home_dir: None,
                    credential: credential.clone(),
                }),
            };
            let identity = |name: &str| KubeContentIdentity {
                artifact_id: odin_domain::ArtifactId::new(name).expect("artifact id"),
                content_digest: Digest::hash(name.as_bytes()),
                byte_len: 64,
            };
            let launch = workload_profile_launch(
                "kube_workload_create",
                &profile,
                plan,
                &KubeLaunchBinding {
                    model: "kubert-mini".to_owned(),
                    budget_policy_digest: Digest::hash(b"lifetime-budget"),
                },
                RunId::new("run:live:lifetime").expect("run id"),
                ProjectId::new("odin").expect("project id"),
                LaneId::new("kubert-odin").expect("lane id"),
                SeatId::new("kubert").expect("seat id"),
                None,
                OperationId::new("op-lifetime").expect("operation id"),
                "kubert-mini".to_owned(),
                JobExtensionLaunch {
                    verifier: "/odin/bin/odind".to_owned(),
                    trusted_extension: "/odin/lib/extension/odin.ts".to_owned(),
                    policy_artifact: odin_domain::ArtifactId::new("lifetime-policy")
                        .expect("artifact id"),
                    policy_digest: Digest::hash(b"lifetime-policy").to_string(),
                },
                identity("lifetime-policy"),
                identity("lifetime-models"),
                vec![identity("surtr-readme")],
                credential,
                target.map(str::to_owned),
            )
            .expect("the admitted workload profile builds a launch");
            assert_eq!(launch.initial_target_node.as_deref(), target);
            assert_eq!(launch.node_selector, profile.placement_labels());
            let seed = format!(
                "workload-create:{}:{}",
                launch.labels.run_id, profile.image.reference
            );
            let historical = Digest::hash(seed.as_bytes());
            match target {
                None => assert_eq!(launch.idempotency_digest, historical),
                Some(node) => {
                    assert_ne!(launch.idempotency_digest, historical);
                    assert_eq!(
                        launch.idempotency_digest,
                        Digest::hash(format!("{seed}:initial-target:{node}").as_bytes())
                    );
                }
            }
            // A declared input follows the launch's own policy and models
            // material, and its bound path is exactly the slot it is staged in.
            assert_eq!(
                launch
                    .staging
                    .inputs
                    .iter()
                    .map(|input| input.artifact_id.as_str())
                    .collect::<Vec<_>>(),
                ["lifetime-policy", "lifetime-models", "surtr-readme"]
            );
            launch
                .validate()
                .expect("declared inputs keep the launch valid");
            let bindings =
                super::super::execution::agent_input_bindings(&launch.staging.inputs[2..]);
            assert_eq!(bindings.len(), 1);
            assert_eq!(bindings[0].artifact_id, "surtr-readme");
            assert_eq!(bindings[0].path, "/var/run/odin/staging/input-2");
            assert_eq!(
                launch.deadline_seconds,
                Some(5400),
                "the declared lifetime is the Job's hard wall clock"
            );
        }
    }

    /// Kubert, asked in one session
    /// to launch state-counter, pc-ticker, residual-watch and heartbeat-svc
    /// (four script pods on one python image), got one pod and three
    /// "operation identity or idempotency digest was reused with different
    /// arguments": every create was bound to the session's run, so all four
    /// shared one Job name and one (run, create, digest) journal identity.
    /// Each profile a session launches now owns its own run under the
    /// session's run, so the launches are distinct Jobs, and a retried
    /// create of the same profile stays the same run.
    #[test]
    fn one_session_launches_several_script_pods_on_one_image() {
        let tool = "kube_workload_create";
        let session = odin_domain::Scope {
            seat: Some(SeatId::new("kubert").expect("seat id")),
            project: Some(ProjectId::new("odin").expect("project id")),
            lane: Some(LaneId::new("kubert-odin").expect("lane id")),
            run: Some(RunId::new("run:live:d460435f-7b34-4ef9-b250-392545fe80d8").expect("run id")),
            ..odin_domain::Scope::default()
        };
        let script = |id: &str| {
            crate::kube_runtime::ScriptLaunchInputs {
            profile: odin_registry::ComposedWorkloadProfile {
                id: id.to_owned(),
                relative_config: format!("registry/workloads/{id}/profile.toml").into(),
                profile: toml::from_str(
                    r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Script pod regression fixture."
harness = "script"

[image]
reference = "docker.io/library/python:3.12-slim@sha256:eeb8088e67610b37583880c7627e3931f087cba55a35810819e34a398f624a47"

[script]
command = ["python3", "-c", "print(1)"]

[seat]
seat = "kubert"
project = "odin"

[network]
allow_hosts = []

[state]
path = "/state"
storage = "1Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/export"

[brief]
text = "Script pod."

[lifetime]
deadline_seconds = 600
"#,
                )
                .expect("script fixture profile"),
            },
            seat: SeatId::new("kubert").expect("seat id"),
            project: ProjectId::new("odin").expect("project id"),
            lane: LaneId::new("kubert-odin").expect("lane id"),
        }
        };
        let binding = KubeLaunchBinding {
            model: "kubert-mini".to_owned(),
            budget_policy_digest: Digest::hash(b"multi-pod-budget"),
        };
        // Placement belongs to each launch, not the portable profile's labels.
        for mode in [
            odin_registry::WorkloadMode::Job,
            odin_registry::WorkloadMode::Service,
        ] {
            let mut inputs = script("portable");
            inputs.profile.profile.mode = mode;
            if mode == odin_registry::WorkloadMode::Service {
                inputs.profile.profile.lifetime = None;
            }
            for capabilities in [vec![], vec!["cpu".to_owned()]] {
                inputs.profile.profile.placement = capabilities;
                let build = |target: Option<&str>| {
                    script_profile_launch(
                        tool,
                        &inputs,
                        Vec::new(),
                        &binding,
                        RunId::new("run:live:portable").expect("run id"),
                        None,
                        OperationId::new("op-portable").expect("operation id"),
                        target.map(str::to_owned),
                    )
                    .expect("portable launch")
                };
                let automatic = build(None);
                let mini = build(Some("mini"));
                let other = build(Some("other-node"));
                assert_eq!(automatic.initial_target_node, None);
                assert_eq!(mini.initial_target_node.as_deref(), Some("mini"));
                assert_eq!(other.initial_target_node.as_deref(), Some("other-node"));
                assert_eq!(
                    mini.node_selector,
                    inputs.profile.profile.placement_labels()
                );
                assert_eq!(mini.node_selector, automatic.node_selector);
                assert_eq!(other.node_selector, automatic.node_selector);
                assert_eq!(mini.service, mode == odin_registry::WorkloadMode::Service);
                assert_eq!(
                    mini.labels.container_identity,
                    automatic.labels.container_identity
                );
                let seed = format!(
                    "script-create:run:live:portable:{}",
                    inputs.profile.profile.image.reference
                );
                assert_eq!(automatic.idempotency_digest, Digest::hash(seed.as_bytes()));
                assert_eq!(
                    mini.idempotency_digest,
                    Digest::hash(format!("{seed}:initial-target:mini").as_bytes())
                );
                assert_ne!(mini.idempotency_digest, automatic.idempotency_digest);
                assert_ne!(mini.idempotency_digest, other.idempotency_digest);
                assert_eq!(
                    build(Some("mini")).idempotency_digest,
                    mini.idempotency_digest
                );
            }
        }
        let launch = |id: &str, operation: &str| {
            let scope = super::super::admission::pod_launch_scope(tool, &session, id, 1)
                .expect("the pod run derives");
            script_profile_launch(
                tool,
                &script(id),
                Vec::new(),
                &binding,
                scope.run.expect("a pod run"),
                None,
                OperationId::new(operation).expect("operation id"),
                None,
            )
            .expect("the script profile builds a launch")
        };
        let launches = [
            launch("state-counter", "op-00000000000000000000000000000001"),
            launch("pc-ticker", "op-00000000000000000000000000000002"),
            launch("residual-watch", "op-00000000000000000000000000000003"),
            launch("heartbeat-svc", "op-00000000000000000000000000000004"),
        ];
        let jobs: std::collections::BTreeSet<_> =
            launches.iter().map(JobLaunch::job_name).collect();
        assert_eq!(jobs.len(), 4, "four profiles, four Jobs");
        let identities: std::collections::BTreeSet<_> = launches
            .iter()
            .map(|launch| (launch.labels.run_id.clone(), launch.idempotency_digest))
            .collect();
        assert_eq!(identities.len(), 4, "four distinct journal identities");
        assert_eq!(
            launches[0].labels.run_id.as_str(),
            "run:live:d460435f-7b34-4ef9-b250-392545fe80d8:pod:state-counter"
        );
        // A retried create of the same profile is the same pod run.
        let again = launch("state-counter", "op-00000000000000000000000000000005");
        assert_eq!(again.job_name(), launches[0].job_name());
        // A create after the session's earlier run
        // of that profile FINISHED (here: cancelled) is a new pod run with
        // its own Job, never a replay of the cancelled one.
        use super::super::admission::{pod_run_generation, PodRunUse};
        let uses = [PodRunUse::Finished, PodRunUse::Finished, PodRunUse::Unused];
        let generation = pod_run_generation(tool, |generation| Ok(uses[generation as usize - 1]))
            .expect("a generation");
        assert_eq!(generation, 3);
        let third =
            super::super::admission::pod_launch_scope(tool, &session, "state-counter", generation)
                .expect("the third run derives")
                .run
                .expect("a pod run");
        assert_eq!(
            third.as_str(),
            "run:live:d460435f-7b34-4ef9-b250-392545fe80d8:pod:state-counter:3"
        );
        // A still-live run is the same pod (idempotent), and the bound holds.
        assert_eq!(
            pod_run_generation(tool, |_| Ok(PodRunUse::Live)).expect("live"),
            1
        );
        assert!(pod_run_generation(tool, |_| Ok(PodRunUse::Finished)).is_err());
        // Digest profile IDs that cannot fit the run's 128-byte limit.
        let long = "p".repeat(100);
        let run = super::super::admission::pod_launch_scope(tool, &session, &long, 1)
            .expect("a long profile id still derives a run")
            .run
            .expect("a pod run");
        assert!(run.as_str().len() <= 128, "{run}");
        assert!(run
            .as_str()
            .starts_with("run:live:d460435f-7b34-4ef9-b250-392545fe80d8:pod:"));
    }

    /// An agent pod launched while a
    /// publication waited for the reload never ran its task (first prompt
    /// refused brain_turn_publication_mismatch, then the reload cut it off).
    #[test]
    fn an_agent_pod_launch_waits_for_a_pending_reload() {
        use super::super::admission::agent_pod_launch_admissible;
        let tool = "kube_workload_create";
        let refused = agent_pod_launch_admissible(tool, true).expect_err("reload pending");
        assert!(
            matches!(&refused, HostToolError::Unavailable { reason, .. }
                if reason.contains("after the restart")),
            "{refused:?}"
        );
        agent_pod_launch_admissible(tool, false).expect("no reload pending");
    }
}
