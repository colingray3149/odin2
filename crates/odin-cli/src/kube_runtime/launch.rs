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

/// What every launch builder takes from the admitted create.
pub(super) struct LaunchRequest<'a> {
    pub(super) tool: &'static str,
    pub(super) binding: &'a KubeLaunchBinding,
    pub(super) run_id: RunId,
    pub(super) project_id: ProjectId,
    pub(super) lane_id: LaneId,
    /// Set when the published profile's identity lane is not the caller's
    /// lane. Admission counts the pod against both, so a profile cannot
    /// spend another lane's pod budget.
    pub(super) budget_lane: Option<LaneId>,
    pub(super) seat_id: SeatId,
    pub(super) attempt: Option<AttemptId>,
    pub(super) operation_id: OperationId,
    pub(super) initial_target_node: Option<String>,
    /// The operator-named run label, carried to the Job's `odin.label` annotation.
    pub(super) label: Option<String>,
}

impl LaunchRequest<'_> {
    /// The host-minted worker and the Job labels: the given attempt, else one
    /// derived from the run and operation, and the run's task.
    fn identity(
        &self,
        model: String,
        container_identity: Digest,
    ) -> Result<(WorkerId, KubeJobLabels), HostToolError> {
        let (tool, run_id) = (self.tool, &self.run_id);
        let worker_id: WorkerId = mint_worker_id()
            .map_err(|error| arguments_error(tool, format!("worker identity rejected: {error}")))?;
        let attempt_id = match self.attempt.clone() {
            Some(attempt_id) => attempt_id,
            None => AttemptId::new(format!(
                "workload-attempt-{}",
                digest16(&format!("attempt:{run_id}:{}", self.operation_id))
            ))
            .map_err(|error| {
                arguments_error(tool, format!("attempt identity rejected: {error}"))
            })?,
        };
        let task_id = TaskId::new(format!(
            "workload-task-{}",
            digest16(&format!("task:{run_id}"))
        ))
        .map_err(|error| arguments_error(tool, format!("task identity rejected: {error}")))?;
        let labels = KubeJobLabels {
            task_id,
            run_id: run_id.clone(),
            attempt_id,
            seat_id: self.seat_id.clone(),
            project_id: self.project_id.clone(),
            lane_id: self.lane_id.clone(),
            model,
            budget_policy_digest: self.binding.budget_policy_digest,
            container_identity,
        };
        Ok((worker_id, labels))
    }

    /// The create's idempotency digest, bound to its initial placement.
    fn idempotency_digest(&self, kind: &str, image: &str) -> Digest {
        initial_placement_digest(
            format!("{kind}:{}:{image}", self.run_id),
            self.initial_target_node.as_deref(),
        )
    }
}

/// Builds the trusted-host launch contract from the admitted published
/// profile: the OCI image is the identity-bearing `base`, the argv payload is
/// the identity-bearing `scripts` under the profile's fixed `/bin/sh -c`
/// executor, the profile's declared GPU reservation and wall-clock deadline
/// ride the launch verbatim, the worker incarnation is host-minted, and
/// staging carries no fabricated inputs (profile Jobs start from the image
/// alone).
pub(super) fn profile_launch(
    request: LaunchRequest<'_>,
    container: &ContainerToml,
    identity: Digest,
) -> Result<JobLaunch, HostToolError> {
    let tool = request.tool;
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
    let (worker_id, labels) = request.identity(request.binding.model.clone(), identity)?;
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
        labels,
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
        idempotency_digest: request.idempotency_digest("create", &container.base),
        operation_id: request.operation_id,
        initial_target_node: request.initial_target_node,
        budget_lane: request.budget_lane,
        label: request.label,
    })
}

/// The admitted workload profile plus the host-staged material its launch consumes.
pub(super) struct WorkloadLaunchParts<'a> {
    pub(super) request: LaunchRequest<'a>,
    pub(super) profile: &'a WorkloadProfileToml,
    pub(super) plan: odin_kube::workload::WorkloadPodPlan,
    pub(super) model: String,
    pub(super) extension: JobExtensionLaunch,
    pub(super) policy_input: KubeContentIdentity,
    pub(super) models_input: KubeContentIdentity,
    pub(super) declared_inputs: Vec<KubeContentIdentity>,
    pub(super) credential: odin_kube::workload::WorkloadCredentialEnv,
}

/// The pinned verifier runs as passive init, reaping children without launching
/// the agent. Only the host attach starts the RPC launcher after UID verification,
/// so startup frames cannot precede their consumer. Declared argv retains kubelet expansion.
pub(super) fn workload_profile_launch(
    parts: WorkloadLaunchParts<'_>,
) -> Result<JobLaunch, HostToolError> {
    let WorkloadLaunchParts {
        request,
        profile,
        plan,
        model,
        extension,
        policy_input,
        models_input,
        declared_inputs,
        credential,
    } = parts;
    let agent = profile.agent().ok_or_else(|| {
        arguments_error(
            request.tool,
            "the workload profile runs no agent harness".to_owned(),
        )
    })?;
    let (worker_id, labels) = request.identity(
        model,
        Digest::hash(
            format!(
                "workload:{}:{}",
                profile.image.reference, agent.runtime.launcher
            )
            .as_bytes(),
        ),
    )?;
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
        labels,
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
        idempotency_digest: request.idempotency_digest("workload-create", &profile.image.reference),
        operation_id: request.operation_id,
        initial_target_node: request.initial_target_node,
        budget_lane: request.budget_lane,
        label: request.label,
    })
}

/// The worker reservation a profile declares, or `None` for the platform defaults.
pub(super) fn profile_resources(
    tool: &'static str,
    profile: &WorkloadProfileToml,
) -> Result<Option<odin_kube::workload::WorkloadResources>, HostToolError> {
    profile
        .resources
        .as_ref()
        .map(|resources| {
            Ok(odin_kube::workload::WorkloadResources {
                cpu: resources.cpu,
                memory_bytes: resources
                    .memory_bytes()
                    .map_err(|reason| arguments_error(tool, reason))?,
            })
        })
        .transpose()
}

/// Script pods use the declared image, argv, resources, and lifecycle without
/// an agent, extension, or session; a declared gateway lane adds its endpoint and key.
pub(super) fn script_profile_launch(
    request: LaunchRequest<'_>,
    inputs: &crate::kube_runtime::ScriptLaunchInputs,
    staged_inputs: Vec<odin_domain::huginn::KubeContentIdentity>,
    vpn: Option<odin_kube::workload::WorkloadVpnTransportPlan>,
) -> Result<JobLaunch, HostToolError> {
    let tool = request.tool;
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
    let plan = odin_kube::workload::WorkloadPodPlan {
        profile: inputs.profile.id.clone(),
        state_mount: profile.state.path.clone(),
        export_mount: profile.export.pod_path.clone(),
        export_host_folder: profile.export.host_folder.clone(),
        state_storage: profile.state.storage.clone(),
        state_storage_class: None,
        allow_hosts: profile.network.allow_hosts.clone(),
        network_open: profile.network.open,
        transport: profile.network.transport,
        vpn,
        report_pdf: false,
        report_downloads_root: None,
        export_deliver_root: None,
        company: None,
        resources: profile_resources(tool, profile)?,
        script_gateway: inputs.gateway.as_ref().map(|gateway| {
            odin_kube::workload::WorkloadScriptGateway {
                lane: gateway.lane.clone(),
                url: gateway.endpoint.as_str().to_owned(),
                gateway: odin_kube::workload::WorkloadGatewayTarget {
                    host: gateway.endpoint.host().to_owned(),
                    port: gateway.endpoint.port(),
                },
                credential: gateway.credential.clone(),
            }
        }),
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
    let (worker_id, labels) = request.identity(request.binding.model.clone(), identity)?;
    let (program, args) = command.split_first().expect("the command is nonempty");
    Ok(JobLaunch {
        labels,
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
        idempotency_digest: request.idempotency_digest("script-create", &profile.image.reference),
        operation_id: request.operation_id,
        initial_target_node: request.initial_target_node,
        budget_lane: request.budget_lane,
        label: request.label,
    })
}

#[cfg(test)]
mod profile_launch_tests {
    use super::*;

    fn request<'a>(
        binding: &'a KubeLaunchBinding,
        run_id: RunId,
        attempt: Option<AttemptId>,
        operation: &str,
        target: Option<&str>,
    ) -> LaunchRequest<'a> {
        LaunchRequest {
            tool: "kube_workload_create",
            binding,
            run_id,
            project_id: ProjectId::new("odin").expect("project id"),
            lane_id: LaneId::new("kubert-odin").expect("lane id"),
            seat_id: SeatId::new("kubert").expect("seat id"),
            attempt,
            operation_id: OperationId::new(operation).expect("operation id"),
            initial_target_node: target.map(str::to_owned),
            budget_lane: None,
            label: None,
        }
    }

    /// One seat session's run, the parent of every pod run it launches.
    fn session() -> odin_domain::Scope {
        odin_domain::Scope {
            seat: Some(SeatId::new("kubert").expect("seat id")),
            project: Some(ProjectId::new("odin").expect("project id")),
            lane: Some(LaneId::new("kubert-odin").expect("lane id")),
            run: Some(RunId::new("run:live:d460435f-7b34-4ef9-b250-392545fe80d8").expect("run id")),
            ..odin_domain::Scope::default()
        }
    }

    /// A create's arguments as the seat sends them.
    fn create_input(arguments: serde_json::Value) -> super::super::admission::ProfileInput {
        serde_json::from_value(arguments).expect("create arguments decode")
    }

    /// The run a create of `profile` with `arguments` binds in [`session`].
    fn pod_run(arguments: serde_json::Value, generation: u32) -> RunId {
        super::super::admission::pod_launch_scope(
            "kube_workload_create",
            &session(),
            &create_input(arguments),
            generation,
        )
        .expect("the pod run derives")
        .run
        .expect("a pod run")
    }

    fn script(id: &str) -> crate::kube_runtime::ScriptLaunchInputs {
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
            gateway: None,
        }
    }

    /// The env a script pod's container receives, read from its launch plan.
    fn script_env(launch: &JobLaunch) -> Vec<(String, Option<String>)> {
        launch
            .workload
            .as_ref()
            .expect("script plan")
            .gateway_env()
            .into_iter()
            .map(|var| (var.name, var.value))
            .collect()
    }

    #[test]
    fn a_script_pod_with_a_gateway_lane_gets_the_gateway_env() {
        let mut inputs = script("gateway-script");
        inputs.profile.profile.seat.gateway_lane = Some("zai-glm".to_owned());
        inputs.gateway = Some(crate::kube_runtime::ScriptGateway {
            lane: "zai-glm".to_owned(),
            endpoint: odin_registry::schema::NodeGatewayEndpoint::parse(
                "http://gateway.example.net:4000/v1",
            )
            .expect("endpoint"),
            credential: odin_kube::workload::WorkloadCredentialEnv {
                env_name: "ODIN_GATEWAY_KEY".to_owned(),
                secret: "gateway-secret".to_owned(),
                key: "master".to_owned(),
            },
        });
        let binding = KubeLaunchBinding {
            model: "kubert-mini".to_owned(),
            budget_policy_digest: Digest::hash(b"script-gateway-budget"),
        };
        let launch = script_profile_launch(
            request(
                &binding,
                RunId::new("run:live:script-gateway").expect("run id"),
                None,
                "op-script-gateway",
                None,
            ),
            &inputs,
            Vec::new(),
            None,
        )
        .expect("the gateway lane script builds a launch");
        assert_eq!(
            script_env(&launch),
            [
                ("ODIN_GATEWAY_KEY".to_owned(), None),
                (
                    "ODIN_GATEWAY_URL".to_owned(),
                    Some("http://gateway.example.net:4000/v1".to_owned())
                ),
                ("ODIN_GATEWAY_LANE".to_owned(), Some("zai-glm".to_owned())),
            ]
        );
        let plan = launch.workload.as_ref().expect("plan");
        let key = plan.gateway_env()[0]
            .value_from
            .clone()
            .expect("secret ref");
        let selector = key.secret_key_ref.expect("secret key ref");
        assert_eq!(
            (selector.name.as_str(), selector.key.as_str()),
            ("gateway-secret", "master"),
            "the key is a Secret reference, never a literal"
        );
        assert!(plan.agent.is_none(), "a script pod runs no agent");
    }

    #[test]
    fn a_profile_launches_only_for_a_seat_it_offers() {
        let mut inputs = script("research");
        let mut caller = session();
        caller.seat = Some(SeatId::new("sinmara").unwrap());
        caller.project = Some(ProjectId::new("personal").unwrap());
        caller.lane = Some(LaneId::new("sinmara-personal").unwrap());
        let allowed = |profile: &odin_registry::schema::WorkloadProfileToml| {
            super::super::admission::require_workload_scope(
                "kube_workload_create",
                &caller,
                profile,
                &inputs.lane,
            )
        };
        assert!(allowed(&inputs.profile.profile).is_err());
        inputs
            .profile
            .profile
            .seats_offered
            .insert(SeatId::new("sinmara").unwrap());
        assert!(allowed(&inputs.profile.profile).is_ok());
    }

    #[test]
    fn different_questions_have_distinct_pod_runs_and_retries_replay() {
        let ask = |prompt: &str| serde_json::json!({"profile": "research", "prompt": prompt});
        assert_ne!(
            pod_run(ask("question one"), 1),
            pod_run(ask("question two"), 1)
        );
        assert_eq!(
            pod_run(ask("question one"), 1),
            pod_run(ask("question one"), 1)
        );
    }

    /// A seat asked for three pods of one profile at once, one question each: one pod ran and two
    /// creates were refused "operation identity or idempotency digest was reused with different
    /// arguments", because all three bound the session's one run of that profile. Through the real
    /// reconciler and journal against a loopback API, three concurrent launches with different inputs are
    /// three Jobs, and a retry of one is that same Job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_session_launches_one_profile_once_per_input() {
        use odin_domain::huginn::KubeContentIdentity;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let api = super::super::fake_api::FakeKubeApi::start().await;
        let ledger = Arc::new(Mutex::new(
            odin_ledger::Ledger::open(dir.path().join("ledger.sqlite3")).expect("ledger"),
        ));
        let channel =
            odin_kernel::recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel");
        let stops = Arc::new(odin_kernel::StopAuthority::new(
            Arc::clone(&ledger),
            channel,
        ));
        let artifacts = dir.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).expect("artifact root");
        let reconciler = odin_kube::JobReconciler::new(
            api.client(dir.path()),
            Arc::clone(&ledger),
            stops,
            Arc::default(),
            artifacts,
        )
        .expect("reconciler");

        let binding = KubeLaunchBinding {
            model: "kubert-mini".to_owned(),
            budget_policy_digest: Digest::hash(b"multi-pod-budget"),
        };
        let store = odin_kube::artifacts::ArtifactStore::new(
            Arc::clone(&ledger),
            dir.path().join("artifacts"),
        );
        let launch = |question: &str, operation: &str, attempt: Option<AttemptId>| {
            let run = pod_run(
                serde_json::json!({ "profile": "asker", "inputs": [question] }),
                1,
            );
            let metadata = super::super::scoped_registration::register_scoped_bytes(
                "kube_workload_create",
                &store,
                &ledger,
                question.as_bytes(),
                question,
                &run,
            )
            .expect("the question is a run-scoped artifact");
            let input = KubeContentIdentity {
                artifact_id: metadata.artifact_id,
                content_digest: metadata.digest,
                byte_len: metadata.size_bytes,
            };
            script_profile_launch(
                request(&binding, run, attempt, operation, None),
                &script("asker"),
                vec![input],
                None,
            )
            .expect("the script profile builds a launch")
        };
        let launches = [
            launch("question-a", "op-00000000000000000000000000000011", None),
            launch("question-b", "op-00000000000000000000000000000012", None),
            launch("question-c", "op-00000000000000000000000000000013", None),
        ];
        let jobs: Vec<String> = launches.iter().map(JobLaunch::job_name).collect();
        let runs: Vec<RunId> = launches
            .iter()
            .map(|launch| launch.labels.run_id.clone())
            .collect();
        for outcome in futures_util::future::join_all(
            launches.into_iter().map(|launch| reconciler.create(launch)),
        )
        .await
        {
            outcome.expect("each question's launch is admitted");
        }
        assert_eq!(
            jobs.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3,
            "three questions, three Jobs"
        );
        let held = api.jobs();
        assert_eq!(held.len(), 3, "{:?}", held.keys());
        for job in &jobs {
            assert!(
                held.contains_key(job),
                "{job} missing from {:?}",
                held.keys()
            );
        }
        // A retried launch re-declares the admitted attempt, as the create path does: same run, same Job.
        let admitted = reconciler
            .stored_launch(&runs[0])
            .expect("journal")
            .map(|stored| stored.labels.attempt_id);
        let retry = launch(
            "question-a",
            "op-00000000000000000000000000000014",
            admitted,
        );
        assert_eq!(retry.labels.run_id, runs[0]);
        reconciler.create(retry).await.expect("a retry replays");
        assert_eq!(api.jobs().len(), 3, "the retry made no fourth Job");
        // Another question bound to a run the journal already admitted is refused.
        let mut shared = launch("question-d", "op-00000000000000000000000000000015", None);
        shared.labels.run_id = runs[0].clone();
        let refused = reconciler.create(shared).await;
        assert!(
            matches!(&refused, Err(odin_kube::KubeError::Conflict { .. })),
            "{refused:?}"
        );
        assert_eq!(api.jobs().len(), 3);
    }

    /// An agent pod launched while a publication waits for the reload would
    /// never run its task, so the launch is refused until the restart.
    #[test]
    fn an_agent_pod_launch_is_refused_while_a_reload_is_pending() {
        use super::super::admission::agent_pod_launch_admissible;
        let tool = "kube_workload_create";
        let refused = agent_pod_launch_admissible(tool, true).expect_err("reload pending");
        assert!(
            matches!(&refused, HostToolError::Unavailable { .. }),
            "{refused:?}"
        );
        agent_pod_launch_admissible(tool, false).expect("no reload pending");
    }
}
