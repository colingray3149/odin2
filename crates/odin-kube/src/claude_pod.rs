use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::api::core::v1::*;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{AttachParams, PostParams};
use odin_domain::{Digest, RunId};
use odin_kernel::stop::{CorrelationId, PodWorkerIdentity, StopAuthority, WorkerId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::exec::{WorkloadExecChannel, WorkloadExecStream, WorkloadLauncherSpec};
use crate::job::{bounded_label_value, JOB_LABEL_RUN_ID};
use crate::object_wait::Settle;
use crate::workload::{egress_policy_name, resolve_hosts, WorkloadGatewayTarget};
use crate::{KubeClient, KubeError};

pub const CONTAINER: &str = "claude-driver";
pub const WORKSPACE: &str = "/workspace/repo";
pub const MCP_CONFIG: &str = "/run/odin-material/mcp.json";
const WORKER: &str = "odin.dev/terminal-worker";
const CORRELATION: &str = "odin.dev/terminal-correlation";
const BOUND: Duration = Duration::from_secs(120);
const OUTPUT_LIMIT: u64 = 1024 * 1024;

// Credentials must not be exposed through Debug or serialization.
pub struct ClaudePodPlan {
    pub run_id: RunId,
    pub session: String,
    pub image: String,
    pub clone_url: String,
    pub revision: String,
    pub branch: String,
    pub account_files: BTreeMap<String, Vec<u8>>,
    pub mcp_config: serde_json::Value,
    pub supervisor_script: Vec<u8>,
    pub git_helper_script: Vec<u8>,
    pub allow_hosts: Vec<String>,
    pub egress_targets: Vec<WorkloadGatewayTarget>,
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
    pub storage_limit: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaudePodReceipt {
    pub worker: String,
    pub identity: PodWorkerIdentity,
    pub branch: String,
    #[serde(default)]
    pub policy_spec: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaudePodPresence {
    Running,
    Absent,
    NotRunning,
}

fn rejected(reason: &str) -> KubeError {
    KubeError::rejected(reason)
}
fn stop_error(operation: &str, error: odin_kernel::stop::StopAuthorityError) -> KubeError {
    KubeError::Storage {
        reason: format!("{operation}: {error}"),
    }
}

pub fn pod_name(run: &RunId) -> String {
    let digest = Digest::hash(format!("odin-kube/claude/v1/{}", run.as_str()).as_bytes());
    let hex: String = digest.as_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("odin-claude-{hex}")
}

fn validate(plan: &ClaudePodPlan) -> Result<(), KubeError> {
    crate::terminal_pod::terminal_correlation(&plan.session)?;
    if !plan
        .image
        .rsplit_once("@sha256:")
        .is_some_and(|(name, hash)| {
            !name.is_empty() && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
        })
    {
        return Err(rejected("Claude image must be digest pinned"));
    }
    // This is a read-only transport, not a URL carrying push credentials.
    if !plan.clone_url.starts_with("git://")
        || plan.clone_url.contains('@')
        || plan.clone_url.chars().any(char::is_whitespace)
    {
        return Err(rejected(
            "Claude clone requires a declared read-only git mirror URL",
        ));
    }
    let name = plan.branch.strip_prefix("claude/").unwrap_or("");
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(rejected("Claude branch must be exactly claude/<name>"));
    }
    if plan.revision.is_empty()
        || plan.revision.starts_with('-')
        || plan.revision.chars().any(char::is_whitespace)
    {
        return Err(rejected("invalid declared clone revision"));
    }
    if !plan.account_files.contains_key(".credentials.json")
        || !plan.account_files.contains_key(".claude.json")
        || plan.account_files.iter().any(|(key, value)| {
            !matches!(key.as_str(), ".credentials.json" | ".claude.json")
                || value.len() > 256 * 1024
                || value.is_empty()
        })
    {
        return Err(rejected(
            "Claude material must contain only selected account files",
        ));
    }
    if !plan.mcp_config.is_object() {
        return Err(rejected("declared MCP config must be an object"));
    }
    let config_size = serde_json::to_vec(&plan.mcp_config)
        .map_err(|error| rejected(&format!("encode Claude MCP config: {error}")))?
        .len();
    if plan.supervisor_script.is_empty()
        || plan.git_helper_script.is_empty()
        || plan
            .supervisor_script
            .len()
            .saturating_add(plan.git_helper_script.len())
            .saturating_add(config_size)
            > 256 * 1024
    {
        return Err(rejected("Claude scripts and MCP material exceed bound"));
    }
    for value in [
        &plan.cpu_request,
        &plan.cpu_limit,
        &plan.memory_request,
        &plan.memory_limit,
        &plan.storage_limit,
    ] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.')
        {
            return Err(rejected("invalid declared resource quantity"));
        }
    }
    Ok(())
}

fn resources(plan: &ClaudePodPlan) -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".into(), Quantity(plan.cpu_request.clone())),
            ("memory".into(), Quantity(plan.memory_request.clone())),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".into(), Quantity(plan.cpu_limit.clone())),
            ("memory".into(), Quantity(plan.memory_limit.clone())),
            (
                "ephemeral-storage".into(),
                Quantity(plan.storage_limit.clone()),
            ),
        ])),
        ..Default::default()
    }
}
fn security() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".into()]),
            add: None,
        }),
        ..Default::default()
    }
}
// PID1 needs identity switching and cross-UID signalling for the Claude child.
fn supervisor_security() -> SecurityContext {
    SecurityContext {
        run_as_user: Some(0),
        run_as_group: Some(0),
        run_as_non_root: Some(false),
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".into()]),
            add: Some(vec!["SETUID".into(), "SETGID".into(), "KILL".into()]),
        }),
        ..Default::default()
    }
}
fn mount(name: &str, path: &str, read_only: bool) -> VolumeMount {
    VolumeMount {
        name: name.into(),
        mount_path: path.into(),
        read_only: Some(read_only),
        ..Default::default()
    }
}
fn bind(metadata: &mut ObjectMeta, worker: &WorkerId, correlation: &CorrelationId) {
    let annotations = metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert(WORKER.into(), worker.as_str().into());
    annotations.insert(CORRELATION.into(), correlation.as_str().into());
}

pub fn desired_pod(plan: &ClaudePodPlan) -> Result<Pod, KubeError> {
    validate(plan)?;
    let name = pod_name(&plan.run_id);
    let mounts = vec![
        mount("workspace", "/workspace", false),
        mount("home", "/home/claude", false),
        mount("tmp", "/tmp", false),
        mount("material", "/run/odin-material", true),
    ];
    let env = vec![
        ("HOME", "/home/claude"),
        ("CLAUDE_CONFIG_DIR", "/home/claude/.claude"),
        ("PATH", "/run/odin-material:/odin/bin:/bin"),
        ("LANG", "C.UTF-8"),
        ("TMPDIR", "/tmp"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
    ]
    .into_iter()
    .map(|(name, value)| EnvVar {
        name: name.into(),
        value: Some(value.into()),
        ..Default::default()
    })
    .collect::<Vec<_>>();
    // Clone parameters are arguments, never shell source.
    let prepare = r#"set -eu
umask 077
mkdir -p /home/claude/.claude
cp /run/odin-material/.credentials.json /home/claude/.claude/.credentials.json
cp /run/odin-material/.claude.json /home/claude/.claude/.claude.json
git clone --no-checkout -- "$1" /workspace/repo
cd /workspace/repo
git checkout --no-track -b "$3" "$2"
git remote set-url --push origin odin::
git config user.name 'Odin Claude driver'
git config user.email 'claude@odin.invalid'
"#;
    let init = Container {
        name: "prepare".into(),
        image: Some(plan.image.clone()),
        command: Some(vec![
            "/bin/sh".into(),
            "-c".into(),
            prepare.into(),
            "prepare".into(),
            plan.clone_url.clone(),
            plan.revision.clone(),
            plan.branch.clone(),
        ]),
        env: Some(env.clone()),
        volume_mounts: Some(mounts.clone()),
        resources: Some(resources(plan)),
        security_context: Some(security()),
        ..Default::default()
    };
    let mut supervisor_mounts = mounts;
    supervisor_mounts.push(mount("supervisor-state", "/run/odin-supervisor", false));
    let carrier = Container {
        name: CONTAINER.into(),
        image: Some(plan.image.clone()),
        command: Some(vec![
            "/bin/python3".into(),
            "-I".into(),
            "/run/odin-material/supervisor.py".into(),
            "serve".into(),
        ]),
        working_dir: Some("/run/odin-supervisor".into()),
        env: Some(env),
        volume_mounts: Some(supervisor_mounts),
        resources: Some(resources(plan)),
        security_context: Some(supervisor_security()),
        ..Default::default()
    };
    let items = [
        ".credentials.json",
        ".claude.json",
        "mcp.json",
        "supervisor.py",
        "publication.json",
        "git-remote-odin",
    ]
    .into_iter()
    .map(|key| KeyToPath {
        key: key.into(),
        path: key.into(),
        mode: Some(if key == "git-remote-odin" {
            0o550
        } else {
            0o440
        }),
    })
    .collect();
    let mut volumes = vec![Volume {
        name: "material".into(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(format!("{name}-material")),
            default_mode: Some(0o440),
            optional: Some(false),
            items: Some(items),
        }),
        ..Default::default()
    }];
    for name in ["workspace", "home", "tmp"] {
        volumes.push(Volume {
            name: name.into(),
            empty_dir: Some(EmptyDirVolumeSource {
                size_limit: Some(Quantity(plan.storage_limit.clone())),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    volumes.push(Volume {
        name: "supervisor-state".into(),
        empty_dir: Some(EmptyDirVolumeSource {
            size_limit: Some(Quantity(plan.storage_limit.clone())),
            ..Default::default()
        }),
        ..Default::default()
    });
    Ok(Pod {
        metadata: ObjectMeta {
            name: Some(name),
            labels: Some(BTreeMap::from([
                (
                    JOB_LABEL_RUN_ID.into(),
                    bounded_label_value(plan.run_id.as_str()),
                ),
                (
                    "odin.dev/claude-session".into(),
                    bounded_label_value(&plan.session),
                ),
            ])),
            ..Default::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Never".into()),
            automount_service_account_token: Some(false),
            enable_service_links: Some(false),
            termination_grace_period_seconds: Some(10),
            containers: vec![carrier],
            init_containers: Some(vec![init]),
            volumes: Some(volumes),
            security_context: Some(PodSecurityContext {
                run_as_non_root: Some(true),
                run_as_user: Some(1000),
                run_as_group: Some(1000),
                fs_group: Some(1000),
                seccomp_profile: Some(SeccompProfile {
                    type_: "RuntimeDefault".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    })
}

pub async fn ensure(
    client: &KubeClient,
    stops: &StopAuthority,
    cluster: &str,
    namespace: &str,
    plan: &ClaudePodPlan,
) -> Result<ClaudePodReceipt, KubeError> {
    let mut pod = desired_pod(plan)?;
    if cluster != client.config.cluster || namespace != client.config.namespace {
        return Err(rejected("Claude cluster or namespace differs from client"));
    }
    if client.config.allowed_nodes.is_empty() {
        return Err(rejected("Claude carrier has no declared admissible nodes"));
    }
    pod.spec
        .as_mut()
        .ok_or_else(|| rejected("Claude pod spec is missing"))?
        .affinity = Some(Affinity {
        node_affinity: Some(NodeAffinity {
            required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                node_selector_terms: vec![NodeSelectorTerm {
                    match_fields: Some(vec![NodeSelectorRequirement {
                        key: "metadata.name".into(),
                        operator: "In".into(),
                        values: Some(client.config.allowed_nodes.iter().cloned().collect()),
                    }]),
                    ..Default::default()
                }],
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    let correlation = crate::terminal_pod::terminal_correlation(&plan.session)?;
    if stops
        .pod_worker_for_correlation(&correlation)
        .map_err(|error| stop_error("find Claude worker", error))?
        .is_some()
    {
        return Err(rejected(
            "Claude session already has a worker; inspect or explicitly stop it",
        ));
    }
    let resolved = resolve_hosts(&plan.allow_hosts, &plan.egress_targets).await?;
    let worker = odin_kernel::stop::mint_worker_id()
        .map_err(|error| KubeError::unavailable(format!("allocate Claude worker: {error}")))?;
    let name = pod_name(&plan.run_id);
    let mut identity = PodWorkerIdentity {
        cluster: cluster.into(),
        namespace: namespace.into(),
        pod_name: name.clone(),
        pod_uid: None,
        policy_name: egress_policy_name(&plan.run_id),
        policy_uid: None,
        secret_name: Some(format!("{name}-material")),
        secret_uid: None,
        correlation_id: correlation.as_str().into(),
    };
    let mut policy = crate::workload::desired_egress_policy(&plan.run_id, &resolved);
    let policy_spec = serde_json::to_value(
        policy
            .spec
            .as_ref()
            .ok_or_else(|| rejected("Claude network policy spec is missing"))?,
    )
    .map_err(|error| rejected(&format!("encode Claude network policy: {error}")))?;
    bind(&mut policy.metadata, &worker, &correlation);
    bind(&mut pod.metadata, &worker, &correlation);
    let mut data: BTreeMap<String, ByteString> = plan
        .account_files
        .iter()
        .map(|(key, value)| (key.clone(), ByteString(value.clone())))
        .collect();
    data.insert(
        "mcp.json".into(),
        ByteString(
            serde_json::to_vec(&plan.mcp_config)
                .map_err(|error| rejected(&format!("encode Claude MCP config: {error}")))?,
        ),
    );
    data.insert(
        "supervisor.py".into(),
        ByteString(plan.supervisor_script.clone()),
    );
    data.insert(
        "git-remote-odin".into(),
        ByteString(plan.git_helper_script.clone()),
    );
    data.insert(
        "publication.json".into(),
        ByteString(
            serde_json::to_vec(
                &serde_json::json!({"session": plan.session, "branch": plan.branch}),
            )
            .map_err(|error| rejected(&format!("encode Claude publication config: {error}")))?,
        ),
    );
    let mut secret = Secret {
        metadata: ObjectMeta {
            name: identity.secret_name.clone(),
            ..Default::default()
        },
        immutable: Some(true),
        type_: Some("Opaque".into()),
        data: Some(data),
        ..Default::default()
    };
    bind(&mut secret.metadata, &worker, &correlation);
    stops
        .register_retained_pod_worker(&worker, &identity, &correlation)
        .map_err(|error| stop_error("register Claude worker", error))?;
    let mut pod_create_attempted = false;
    let mut create_uncertain = false;
    let launch = async {
        let policy = tokio::time::timeout(
            client.request_timeout(),
            client.network_policies().create(&PostParams::default(), &policy),
        )
        .await
        .map_err(|error| {
            create_uncertain = true;
            KubeError::unavailable(format!("create Claude policy timed out: {error}"))
        })?
        .map_err(|error| {
            create_uncertain = !matches!(&error, kube::Error::Api(response) if (400..500).contains(&response.code));
            KubeError::unavailable(format!("create Claude policy: {error}"))
        })?;
        identity.policy_uid = Some(policy.metadata.uid
            .ok_or_else(|| rejected("created Claude policy has no UID"))?);
        stops.update_pod_worker_identity(&worker, &identity)
            .map_err(|error| stop_error("record Claude policy UID", error))?;
        let secret = tokio::time::timeout(
            client.request_timeout(),
            client.secrets().create(&PostParams::default(), &secret),
        )
        .await
        .map_err(|error| {
            create_uncertain = true;
            KubeError::unavailable(format!("create Claude material timed out: {error}"))
        })?
        .map_err(|error| {
            create_uncertain = !matches!(&error, kube::Error::Api(response) if (400..500).contains(&response.code));
            // API messages can echo the submitted credentials.
            let cause = match error {
                kube::Error::Api(response) => format!("{} (HTTP {})", response.reason, response.code),
                error => error.to_string(),
            };
            KubeError::unavailable(format!("create Claude material: {cause}"))
        })?;
        identity.secret_uid = Some(secret.metadata.uid
            .ok_or_else(|| rejected("created Claude material has no UID"))?);
        stops.update_pod_worker_identity(&worker, &identity)
            .map_err(|error| stop_error("record Claude material UID", error))?;
        // Even an unanswered create may start a workspace; never discard it automatically.
        pod_create_attempted = true;
        let pod = tokio::time::timeout(
            client.request_timeout(),
            client.pods().create(&PostParams::default(), &pod),
        )
        .await
        .map_err(|error| KubeError::unavailable(format!("create Claude pod timed out: {error}")))?
        .map_err(|error| KubeError::unavailable(format!("create Claude pod: {error}")))?;
        identity.pod_uid = Some(pod.metadata.uid
            .ok_or_else(|| rejected("created Claude pod has no UID"))?);
        stops.update_pod_worker_identity(&worker, &identity)
            .map_err(|error| stop_error("record Claude pod UID", error))?;
        Ok::<(), KubeError>(())
    }.await;
    let handle = ClaudePodReceipt {
        worker: worker.as_str().into(),
        identity,
        branch: plan.branch.clone(),
        policy_spec: Some(policy_spec),
    };
    if let Err(error) = launch {
        if pod_create_attempted {
            tracing::warn!(worker = %worker, error = %error,
                "Claude launch failed; inspect the retained workspace before stopping it");
        } else if create_uncertain {
            tracing::warn!(worker = %worker, error = %error,
                "Claude resource creation is uncertain; inspect and stop the recorded worker");
        } else {
            let cleanup = (|| {
                let (_, identity, _) = stops
                    .pod_worker_for_correlation(&correlation)
                    .map_err(|error| stop_error("find Claude worker for cleanup", error))?
                    .ok_or_else(|| rejected("Claude worker missing during launch cleanup"))?;
                stops
                    .admit_pod_stop(&worker, &identity)
                    .map_err(|error| stop_error("admit Claude launch cleanup", error))?;
                stops
                    .stop_pod_worker(&worker)
                    .map_err(|error| stop_error("clean up Claude launch", error))?;
                Ok::<(), KubeError>(())
            })();
            if let Err(cleanup) = cleanup {
                tracing::error!(worker = %worker, error = %cleanup,
                    "Claude launch cleanup failed; stop the recorded worker");
            }
        }
        return Err(error);
    }
    let ready = crate::object_wait::wait_for(
        &client.pods(),
        &handle.identity.pod_name,
        BOUND,
        || "Claude carrier did not become ready; inspect the retained workspace".into(),
        |pod| match pod {
            Some(pod) => match presence(pod, &handle) {
                Err(error) => Settle::Fail(error),
                Ok(ClaudePodPresence::Running)
                    if pod
                        .status
                        .as_ref()
                        .and_then(|s| s.container_statuses.as_ref())
                        .is_some_and(|s| s.iter().any(|s| s.name == CONTAINER && s.ready)) =>
                {
                    Settle::Done(())
                }
                Ok(_)
                    if pod
                        .status
                        .as_ref()
                        .and_then(|s| s.phase.as_deref())
                        .is_some_and(|p| matches!(p, "Failed" | "Succeeded")) =>
                {
                    Settle::Fail(KubeError::unavailable(
                        "Claude carrier ended before readiness",
                    ))
                }
                _ => Settle::Wait,
            },
            None => Settle::Wait,
        },
    )
    .await;
    if let Err(error) = ready {
        tracing::warn!(worker = %worker, error = %error,
            "Claude launch failed; inspect the retained workspace before stopping it");
        return Err(error);
    }
    Ok(handle)
}

fn presence(pod: &Pod, handle: &ClaudePodReceipt) -> Result<ClaudePodPresence, KubeError> {
    let annotations = pod.metadata.annotations.as_ref();
    if handle.identity.pod_uid.is_none()
        || pod.metadata.uid != handle.identity.pod_uid
        || pod.metadata.name.as_deref() != Some(handle.identity.pod_name.as_str())
        || annotations.and_then(|a| a.get(WORKER)).map(String::as_str)
            != Some(handle.worker.as_str())
        || annotations
            .and_then(|a| a.get(CORRELATION))
            .map(String::as_str)
            != Some(handle.identity.correlation_id.as_str())
    {
        return Err(rejected("Claude pod ownership changed"));
    }
    if !pod
        .spec
        .as_ref()
        .is_some_and(|s| s.containers.iter().any(|c| c.name == CONTAINER))
    {
        return Err(rejected("Claude carrier container absent"));
    }
    Ok(
        if pod.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running") {
            ClaudePodPresence::Running
        } else {
            ClaudePodPresence::NotRunning
        },
    )
}

pub async fn inspect(
    client: &KubeClient,
    handle: &ClaudePodReceipt,
) -> Result<ClaudePodPresence, KubeError> {
    if handle.identity.cluster != client.config.cluster
        || handle.identity.namespace != client.config.namespace
    {
        return Err(rejected(
            "Claude pod belongs to another cluster or namespace",
        ));
    }
    let pod = tokio::time::timeout(
        client.request_timeout(),
        client.pods().get_opt(&handle.identity.pod_name),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("inspect Claude pod timed out: {error}")))?
    .map_err(|error| KubeError::unavailable(format!("inspect Claude pod: {error}")))?;
    pod.as_ref()
        .map_or(Ok(ClaudePodPresence::Absent), |pod| presence(pod, handle))
}

pub async fn exec(
    client: &KubeClient,
    handle: &ClaudePodReceipt,
    launcher: &WorkloadLauncherSpec,
) -> Result<WorkloadExecStream, KubeError> {
    let argv = launcher
        .argv()
        .map_err(|error| rejected(&format!("compose Claude launcher: {error}")))?;
    if inspect(client, handle).await? != ClaudePodPresence::Running {
        return Err(KubeError::unavailable("Claude pod is not running"));
    }
    let params = AttachParams {
        stdin: true,
        stdout: true,
        stderr: true,
        tty: false,
        ..Default::default()
    }
    .container(CONTAINER);
    let process = tokio::time::timeout(
        client.request_timeout(),
        client.pods().exec(&handle.identity.pod_name, argv, &params),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("attach Claude exec timed out: {error}")))?
    .map_err(|error| KubeError::unavailable(format!("attach Claude exec: {error}")))?;
    // Kubernetes exec has no UID precondition, so check again before exposing streams.
    if inspect(client, handle).await? != ClaudePodPresence::Running {
        return Err(rejected("Claude identity changed during attach"));
    }
    let stream = crate::exec::decompose(WorkloadExecChannel {
        pod: handle.identity.pod_name.clone(),
        process,
    })?;
    if stream.stderr.is_none() {
        return Err(KubeError::unavailable("Claude exec did not expose stderr"));
    }
    Ok(stream)
}

// Command stderr may contain secrets and must not appear in errors.
pub async fn command(
    client: &KubeClient,
    handle: &ClaudePodReceipt,
    launcher: &WorkloadLauncherSpec,
) -> Result<Vec<u8>, KubeError> {
    let stream = exec(client, handle, launcher).await?;
    let result = tokio::time::timeout(Duration::from_secs(30), async move {
        let WorkloadExecStream {
            mut stdin,
            stdout,
            stderr,
            exit,
            ..
        } = stream;
        stdin.shutdown().await.map_err(|error| {
            KubeError::unavailable(format!("close Claude command stdin: {error}"))
        })?;
        drop(stdin);
        let output = async move {
            let mut bytes = Vec::new();
            stdout
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|error| {
                    KubeError::unavailable(format!("read Claude command output: {error}"))
                })?;
            if bytes.len() as u64 > OUTPUT_LIMIT {
                return Err(rejected("Claude command output exceeds bound"));
            }
            Ok(bytes)
        };
        let errors = async move {
            if let Some(stderr) = stderr {
                let mut sink = tokio::io::sink();
                let count = tokio::io::copy(&mut stderr.take(OUTPUT_LIMIT + 1), &mut sink)
                    .await
                    .map_err(|error| {
                        KubeError::unavailable(format!("drain Claude command stderr: {error}"))
                    })?;
                if count > OUTPUT_LIMIT {
                    return Err(rejected("Claude command stderr exceeds bound"));
                }
            }
            Ok::<(), KubeError>(())
        };
        let status = async move {
            if let Some(reason) = exit.await {
                Err(KubeError::unavailable(format!(
                    "run Claude inspection command: {reason}"
                )))
            } else {
                Ok(())
            }
        };
        let (bytes, (), ()) = tokio::try_join!(output, errors, status)?;
        Ok(bytes)
    })
    .await
    .map_err(|error| {
        KubeError::unavailable(format!("run Claude inspection command timed out: {error}"))
    })?;
    result
}

// The caller must publish or explicitly discard workspace changes before stopping.
pub fn stop(stops: &StopAuthority, handle: &ClaudePodReceipt) -> Result<(), KubeError> {
    let worker = WorkerId::new(&handle.worker)
        .map_err(|error| rejected(&format!("parse Claude worker: {error}")))?;
    stops
        .admit_pod_stop(&worker, &handle.identity)
        .map_err(|error| stop_error("admit Claude stop", error))?;
    let outcome = stops
        .stop_pod_worker(&worker)
        .map_err(|error| stop_error("stop Claude pod", error))?;
    if outcome.verdict != odin_domain::StopVerdictTag::Stopped {
        return Err(KubeError::unavailable(format!(
            "stop Claude pod {worker}: {:?}",
            outcome.evidence.missing
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
