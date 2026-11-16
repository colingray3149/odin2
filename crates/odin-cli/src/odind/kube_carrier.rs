//! Kube-admitted workload carrier and pod exec transport.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_cli::browser_runtime;
use odin_domain::extension_policy::{EXTENSION_POLICY_DIGEST_ENV, EXTENSION_POLICY_PATH_ENV};
use odin_domain::huginn as live;
use odin_domain::huginn::{LiveError, SessionManifest};
use odin_kube::exec::{decompose, exec_fixed, WorkloadExecStream, WorkloadLauncherSpec};
use odin_kube::job::{JobExtensionLaunch, JobModelsConfigLaunch};
use odin_ledger::stop::JobStopAction;
use odin_omp::process::{
    HarnessStdin, OmpProcessSpec, RemoteAttachError, RemoteExit, RemoteHarnessAdmission,
    RemoteHarnessChannel, RemoteHarnessFactory,
};
use odin_types::WorkerId;

use super::{open_pod_browser, KubeRuntimeCell};

/// Transport constant of the in-image env executable the exec argv is
/// composed through (imageRoot coreutils; build-validated in-image by the
/// image contract). Mechanism only — never a profile field.
const WORKLOAD_ENV_EXECUTABLE: &str = "/bin/env";
/// Bounds of the composed env carriage: few, bounded, NUL-free pairs.
const WORKLOAD_ENV_MAX_PAIRS: usize = 16;
const WORKLOAD_ENV_PAIR_BYTES_MAX: usize = 4096;

fn bad_env(reason: String) -> RemoteAttachError {
    RemoteAttachError { detail: reason }
}

fn validate_env_pair(key: &str, value: &str) -> Result<(), RemoteAttachError> {
    if key.is_empty() || value.contains('\0') || key.contains('\0') {
        return Err(bad_env(
            "workload env pair is empty-keyed or carries NUL".to_owned(),
        ));
    }
    if key.len() > 128 || value.len() > WORKLOAD_ENV_PAIR_BYTES_MAX {
        return Err(bad_env(
            "workload env pair exceeds the composed bounds".to_owned(),
        ));
    }
    Ok(())
}

/// The kube-admitted remote carrier resolver: proves one workload binding's
/// operation against the durable kube launch journal, then attaches the
/// exact admitted pod exec channel of that run. The pinned launcher,
/// extension binding, and digest-pinned image come from the durable launch
/// record and the pinned image identity — never from a live declaration
/// re-read. No local fallback exists.
pub(crate) struct KubeWorkloadCarrier {
    cell: Arc<KubeRuntimeCell>,
    /// The controller's pinned OMP source revision, carried into the remote
    /// spec exactly as the local composition pins it.
    omp_revision: String,
    /// Browser tools open an in-pod browser through these routes.
    browsers: Arc<browser_runtime::BrowserRoutes>,
    /// The profiles whose pods run their own browser.
    browser_profiles: std::collections::BTreeSet<String>,
    /// Pod-exec capabilities reach a session's pod through these bindings.
    pod_sessions: Arc<odin_omp::host_tools::pod_exec::PodSessions>,
    /// Each profile's recon plan, the exec that runs a pod's seeds, and where their findings go.
    recon: crate::live::seed_recon::ReconCarriage,
}

impl KubeWorkloadCarrier {
    pub fn new(
        cell: Arc<KubeRuntimeCell>,
        omp_revision: String,
        browsers: Arc<browser_runtime::BrowserRoutes>,
        browser_profiles: std::collections::BTreeSet<String>,
        pod_sessions: Arc<odin_omp::host_tools::pod_exec::PodSessions>,
        recon: crate::live::seed_recon::ReconCarriage,
    ) -> Self {
        Self {
            cell,
            omp_revision,
            browsers,
            browser_profiles,
            pod_sessions,
            recon,
        }
    }
}

#[async_trait::async_trait]
impl odin_omp::live::runtime::WorkloadCarrierPort for KubeWorkloadCarrier {
    async fn carrier_for(
        &self,
        binding: &odin_domain::huginn::WorkloadSessionBinding,
        manifest: &SessionManifest,
    ) -> Result<Arc<dyn RemoteHarnessFactory>, LiveError> {
        let control = self.cell.control().ok_or_else(|| {
            LiveError::unavailable("workload_carrier", "the k3s API server is unreachable")
        })?;
        let reconciler = control.reconciler();
        let Some((run, launch)) = reconciler
            .operation_launch(&binding.operation)
            .map_err(|error| LiveError::unavailable("workload_carrier", error))?
        else {
            return Err(LiveError::unavailable(
                "workload_carrier",
                format!(
                    "operation {} admits no durable launch record",
                    binding.operation
                ),
            ));
        };
        // Declared identity must agree across binding, durable launch
        // record, and live manifest: profile, seat, and project. Node
        // placement is Kubernetes-selected and carries no durable field;
        // serving-node identity was proven at open against the seat
        // binding's allowed-node set.
        let Some(plan) = launch.workload.as_ref() else {
            return Err(LiveError::unavailable(
                "workload_carrier",
                "the admitted launch carries no workload plan",
            ));
        };
        let Some(extension) = launch.extension.as_ref() else {
            return Err(LiveError::unavailable(
                "workload_carrier",
                "the admitted launch carries no extension binding",
            ));
        };
        let mut staged_paths = reconciler
            .staged_paths(&run)
            .map_err(|error| LiveError::unavailable("workload_carrier", error))?;
        let Some(staged_policy_path) = staged_paths.remove(&extension.policy_artifact) else {
            return Err(LiveError::unavailable(
                "workload_carrier",
                format!(
                    "the staged policy artifact {} has no recorded staging path for run {run}",
                    extension.policy_artifact
                ),
            ));
        };
        let Some(models) = launch.models_config.as_ref() else {
            return Err(LiveError::unavailable(
                "workload_carrier",
                "the admitted launch carries no models document",
            ));
        };
        let Some(staged_models_path) = staged_paths.remove(&models.config_artifact) else {
            return Err(LiveError::unavailable(
                "workload_carrier",
                format!(
                    "the staged models artifact {} has no recorded staging path for run {run}",
                    models.config_artifact
                ),
            ));
        };
        // The unique per-run agent dir lives under the declared state mount:
        // session-persistent, never the read-only staging mount, never a
        // shared persistent user state.
        let agent_dir = format!("{}/.omp-agent/{}", plan.state_mount, run);
        let spec = compose_remote_spec(
            &AdmittedCarrierComposition {
                extension,
                models,
                staged_policy_path: &staged_policy_path,
                staged_models_path: &staged_models_path,
                agent_dir: &agent_dir,
            },
            plan,
            &self.omp_revision,
        )
        .map_err(|reason| LiveError::InvalidRequest {
            code: "workload_carrier_spec".to_owned(),
            message: reason,
        })?;
        if plan.profile != binding.profile
            || launch.labels.run_id != run
            || launch.labels.seat_id != manifest.seat_id
            || launch.labels.project_id != manifest.project_id
        {
            return Err(LiveError::InvalidRequest {
                code: "workload_carrier_identity".to_owned(),
                message: "the admitted launch record disagrees with the session binding".to_owned(),
            });
        }
        let owner =
            odin_domain::SessionId::new(manifest.session_id.to_string()).map_err(|error| {
                LiveError::InvalidRequest {
                    code: "pod_session_owner".to_owned(),
                    message: error.to_string(),
                }
            })?;
        let target = odin_omp::host_tools::pod_exec::PodTarget {
            run: run.clone(),
            export_dir: plan.export_mount.clone(),
            network_transport: plan.transport,
            recon: self.recon.plans.get(&plan.profile).cloned(),
        };
        self.pod_sessions.bind(owner.clone(), target.clone());
        self.recon.seed(target, &binding.seeds, manifest.session_id);
        // Reserve the derived browser session for reattachment, then open it when the pod runs.
        if self.browser_profiles.contains(&plan.profile) {
            let session = live::pod_browser_session_id(&manifest.session_id);
            if self.browsers.reserve(session, owner) {
                tokio::spawn(open_pod_browser(
                    reconciler.exec_client(),
                    run.clone(),
                    plan.clone(),
                    session,
                    Arc::clone(&self.browsers),
                ));
            }
        }
        Ok(Arc::new(KubeExecHarness {
            client: reconciler.exec_client(),
            run,
            worker_id: launch.worker_id.clone(),
            admission: RemoteHarnessAdmission {
                profile: binding.profile.clone(),
                image: launch.image.clone(),
            },
            spec,
        }))
    }
}

/// One admitted pod exec channel factory: the host-admitted remote
/// harness of a workload session. The composed remote spec (verifier entry,
/// staged policy carriage, declared launcher) and the digest-pinned image
/// are the durable launch record's, carried as admission evidence.
struct KubeExecHarness {
    client: odin_kube::KubeClient,
    run: odin_domain::RunId,
    worker_id: WorkerId,
    admission: RemoteHarnessAdmission,
    spec: OmpProcessSpec,
}

#[async_trait::async_trait]
impl RemoteHarnessFactory for KubeExecHarness {
    async fn attach(
        &self,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<RemoteHarnessChannel, RemoteAttachError> {
        // Env carriage is argv-only through the image's own /bin/env
        // (coreutils; build-validated in-image by the image contract):
        // ["/bin/env", "--", K=V..., <composed remote spec argv>...].
        // Plain argv, no shell, no interpolation, no stdin protocol; only
        // the caller-composed capability-identity pairs ride here, exactly
        // as composed — never wholesale host env, never secrets or paths.
        // The composed spec argv itself starts at the in-image verifier
        // entrypoint and carries the declared launcher verbatim after `--`.
        let mut arguments: Vec<String> = Vec::with_capacity(env.len() + args.len() + 2);
        if !env.is_empty() {
            if env.len() > WORKLOAD_ENV_MAX_PAIRS {
                return Err(bad_env(format!(
                    "env carries {} pairs, over the {} pair bound",
                    env.len(),
                    WORKLOAD_ENV_MAX_PAIRS
                )));
            }
            arguments.push("--".into());
            for (key, value) in env {
                validate_env_pair(key, value)?;
                arguments.push(format!("{key}={value}"));
            }
        }
        // The composed spec's executable is the in-image verifier entry —
        // the first real argv element of the exec, exactly as the remote
        // API composes it: [/bin/env, --, K=V..., <verifier>, "workload-exec", ...].
        arguments.push(self.spec.executable.to_string_lossy().into_owned());
        arguments.extend(args.iter().cloned());
        let spec = WorkloadLauncherSpec {
            launcher_path: WORKLOAD_ENV_EXECUTABLE.to_owned(),
            arguments,
        };
        let attached = exec_fixed(
            &self.client,
            &self.run,
            odin_kube::exec::JobExecTarget::Worker,
            &spec,
        )
        .await
        .map_err(|error| RemoteAttachError {
            detail: error.to_string(),
        })?;
        let stream = decompose(attached).map_err(|error| RemoteAttachError {
            detail: error.to_string(),
        })?;
        Ok(map_channel(stream))
    }

    fn job_worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    fn stop_action(&self) -> JobStopAction {
        JobStopAction::Delete
    }

    fn admission(&self) -> &RemoteHarnessAdmission {
        &self.admission
    }

    fn process_spec(&self) -> OmpProcessSpec {
        self.spec.clone()
    }
}

/// The admitted carrier composition of one workload run: the launch
/// record's own verified bindings paired with the exact staged read-only
/// paths the reconciler recorded for them, plus the unique per-run agent
/// dir under the declared state mount. Every member is journaled-with-
/// the-launch or admission-resolved state; nothing is inferred from the
/// environment, argv shapes, or path conventions.
struct AdmittedCarrierComposition<'a> {
    extension: &'a JobExtensionLaunch,
    models: &'a JobModelsConfigLaunch,
    staged_policy_path: &'a str,
    staged_models_path: &'a str,
    agent_dir: &'a str,
}

/// Composes the remote carrier's process spec. The in-image verifier entry —
/// the image identity's own `odind`, whose `workload-exec` mode re-proves
/// the staged policy bytes and the pinned extension bytes with the existing
/// `ExtensionPolicyV1` verifier pair — carries the declared launcher
/// verbatim after `--` and execs it only on success. The policy binding
/// travels as explicit typed arguments; the extension path is exactly the
/// image identity's declared in-image value, never a host path and never a
/// store path.
fn compose_remote_spec(
    composition: &AdmittedCarrierComposition<'_>,
    plan: &odin_kube::workload::WorkloadPodPlan,
    omp_revision: &str,
) -> Result<OmpProcessSpec, String> {
    let extension = composition.extension;
    let models = composition.models;
    let staged_policy_path = composition.staged_policy_path;
    let staged_models_path = composition.staged_models_path;
    let agent_dir = composition.agent_dir;
    let state_mount = plan.state_mount.as_str();
    let verifier = extension.verifier.as_str();
    let launcher = plan
        .agent
        .as_ref()
        .ok_or_else(|| format!("workload {} runs no agent harness to attach", plan.profile))?
        .launcher
        .as_str();
    if !odin_registry::schema::valid_pod_path(verifier) {
        return Err(format!(
            "the in-image verifier path {verifier:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(launcher) {
        return Err(format!(
            "the declared launcher path {launcher:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(staged_policy_path) {
        return Err(format!(
            "the staged policy path {staged_policy_path:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(staged_models_path) {
        return Err(format!(
            "the staged models path {staged_models_path:?} is invalid"
        ));
    }
    if !odin_registry::schema::valid_pod_path(agent_dir) {
        return Err(format!("the agent dir {agent_dir:?} is invalid"));
    }
    odin_domain::extension_policy::validate_digest(&extension.policy_digest)
        .map_err(|error| format!("the launch policy digest is malformed: {error}"))?;
    odin_domain::extension_policy::validate_digest(&models.config_digest)
        .map_err(|error| format!("the models config digest is malformed: {error}"))?;
    let mut explicit_args = vec![
        "workload-exec".to_owned(),
        "--extension-policy".to_owned(),
        staged_policy_path.to_owned(),
        "--extension-policy-digest".to_owned(),
        extension.policy_digest.clone(),
        "--models-config".to_owned(),
        staged_models_path.to_owned(),
        "--models-config-digest".to_owned(),
        models.config_digest.clone(),
        "--agent-dir".to_owned(),
        agent_dir.to_owned(),
        "--state-mount".to_owned(),
        state_mount.to_owned(),
        "--credential-env".to_owned(),
        models.credential_env.clone(),
        "--working-dir".to_owned(),
        state_mount.to_owned(),
        "--trusted-extension".to_owned(),
        extension.trusted_extension.clone(),
        "--".to_owned(),
        launcher.to_owned(),
    ];
    // Share tool-exposure flags with local launches: read only, never `--no-tools`.
    explicit_args.extend(odin_omp::process::governed_harness_args(
        std::path::Path::new(&extension.trusted_extension),
    ));
    let explicit_env = vec![
        (
            EXTENSION_POLICY_PATH_ENV.to_owned(),
            staged_policy_path.to_owned(),
        ),
        (
            EXTENSION_POLICY_DIGEST_ENV.to_owned(),
            extension.policy_digest.clone(),
        ),
        ("PI_CODING_AGENT_DIR".to_owned(), agent_dir.to_owned()),
    ];
    Ok(OmpProcessSpec {
        executable: PathBuf::from(verifier),
        cwd: PathBuf::from(state_mount),
        explicit_args,
        explicit_env,
        expected_source_revision: omp_revision.to_owned(),
        startup_timeout: StdDuration::from_secs(120),
        drain_timeout: StdDuration::from_secs(10),
        kill_timeout: StdDuration::from_secs(5),
    })
}

/// Maps the kube exec stream halves into the transport-agnostic remote
/// harness channel the process boundary consumes: every carrier outcome is
/// mapped onto the typed [`RemoteExit`] — `None` (clean channel close) is
/// clean, `Some(reason)` (Failure status, missing verdict, or canceled
/// wait) is unclean with the exact reason.
fn map_channel(stream: WorkloadExecStream) -> RemoteHarnessChannel {
    RemoteHarnessChannel {
        stdin: Box::new(ExecStdin {
            writer: Some(stream.stdin),
        }),
        stdout: Box::new(stream.stdout),
        stderr: stream.stderr,
        exit: Box::pin(async move {
            match stream.exit.await {
                Some(reason) => RemoteExit {
                    status: None,
                    clean: false,
                    failure: Some(reason),
                },
                None => RemoteExit {
                    status: None,
                    clean: true,
                    failure: None,
                },
            }
        }),
    }
}

/// The exec stdin half: ordered framed writes while the carrier is
/// attached, graceful stdin EOF on shutdown.
struct ExecStdin {
    writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
}

#[async_trait::async_trait]
impl HarnessStdin for ExecStdin {
    async fn write_all(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        match self.writer.as_mut() {
            Some(writer) => tokio::io::AsyncWriteExt::write_all(writer, &bytes).await,
            None => Err(std::io::Error::other(
                "the exec stdin half is already closed",
            )),
        }
    }

    fn shutdown(mut self: Box<Self>) -> std::io::Result<()> {
        // Graceful: close stdin EOF. The carrier drains, exits, and the
        // owned exit waiter resolves from the real carrier status.
        self.writer = None;
        Ok(())
    }
}
