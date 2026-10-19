use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    Affinity, Capabilities, Container, EmptyDirVolumeSource, EnvVar, HostPathVolumeSource,
    NodeAffinity, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, Pod, PodSecurityContext,
    PodSpec, ResourceRequirements, SeccompProfile, SecurityContext, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use odin_domain::{Digest, RunId};
use odin_kernel::stop::{CorrelationId, StopAuthority, WorkerId};

use crate::client::{KubeClient, KubeError};
use crate::job::{bounded_label_value, JOB_LABEL_RUN_ID};
use crate::object_wait::Settle;
use crate::workload::{egress_policy_name, resolve_hosts, WorkloadGatewayTarget};

mod backend;
pub use backend::KubernetesPodBackend;
const WORKER_ANNOTATION: &str = "odin.dev/terminal-worker";
const CORRELATION_ANNOTATION: &str = "odin.dev/terminal-correlation";

pub const TERMINAL_CONTAINER: &str = "agent";
/// Lives in the tmux server's emptyDir mount.
pub const TERMINAL_SOCKET: &str = "/run/odin-term/tmux.sock";
pub const TERMINAL_LABEL_SESSION: &str = "odin.dev/terminal-session";

const START_BOUND: std::time::Duration = std::time::Duration::from_secs(120);

// Launches share a lock with startup cleanup of rows left by an earlier process.
pub type PodLifecycle = tokio::sync::Mutex<bool>;

pub async fn pod_lifecycle_guard<'a>(
    stops: &StopAuthority,
    lifecycle: &'a PodLifecycle,
) -> Result<tokio::sync::MutexGuard<'a, bool>, odin_kernel::stop::StopAuthorityError> {
    let mut recovered = lifecycle.lock().await;
    if !*recovered {
        for outcome in stops.recover_pending_pods(None)? {
            tracing::info!(
                "terminal pod recovered worker={} verdict={:?}",
                outcome.worker_id,
                outcome.verdict
            );
        }
        *recovered = true;
    }
    Ok(recovered)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalPodPlan {
    pub run_id: RunId,
    pub session: String,
    pub image: String,
    pub node: String,
    pub uid: i64,
    pub gid: i64,
    pub home: String,
    pub workspace: String,
    pub runtime: Option<String>,
    // Files with extensions mount as files rather than directories.
    pub credentials: Vec<String>,
    pub tmux: String,
    pub allow_hosts: Vec<String>,
    pub bridge: Option<WorkloadGatewayTarget>,
    pub git_mirror: Option<WorkloadGatewayTarget>,
}

/// The terminal pod's name for one run: stable, so a reclaim finds it.
pub fn terminal_pod_name(run_id: &RunId) -> String {
    let digest = Digest::hash(format!("odin-kube/terminal/v1/{}", run_id.as_str()).as_bytes());
    let hex: String = digest.as_bytes()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("odin-term-{hex}")
}

fn labels(plan: &TerminalPodPlan) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            JOB_LABEL_RUN_ID.to_owned(),
            bounded_label_value(plan.run_id.as_str()),
        ),
        (
            TERMINAL_LABEL_SESSION.to_owned(),
            bounded_label_value(&plan.session),
        ),
    ])
}

fn host_path(name: &str, path: &str, read_only: bool, kind: &str) -> (Volume, VolumeMount) {
    (
        Volume {
            name: name.to_owned(),
            host_path: Some(HostPathVolumeSource {
                path: path.to_owned(),
                type_: Some(kind.to_owned()),
            }),
            ..Default::default()
        },
        VolumeMount {
            name: name.to_owned(),
            mount_path: path.to_owned(),
            read_only: Some(read_only),
            ..Default::default()
        },
    )
}

fn empty_dir(name: &str, path: &str) -> (Volume, VolumeMount) {
    (
        Volume {
            name: name.to_owned(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        },
        VolumeMount {
            name: name.to_owned(),
            mount_path: path.to_owned(),
            ..Default::default()
        },
    )
}

pub fn desired_terminal_pod(plan: &TerminalPodPlan) -> Pod {
    let mut mounted = vec![
        empty_dir("home", &plan.home),
        empty_dir("run", "/run/odin-term"),
        host_path("workspace", &plan.workspace, false, "Directory"),
    ];
    if let Some(runtime) = &plan.runtime {
        mounted.push(host_path("runtime", runtime, true, "Directory"));
    }
    for (index, credential) in plan.credentials.iter().enumerate() {
        let kind = if std::path::Path::new(credential).extension().is_some() {
            "File"
        } else {
            "Directory"
        };
        mounted.push(host_path(
            &format!("credential-{index}"),
            credential,
            false,
            kind,
        ));
    }
    let (volumes, mounts): (Vec<_>, Vec<_>) = mounted.into_iter().unzip();
    let env = [
        ("HOME", plan.home.as_str()),
        ("PATH", "/odin/bin:/bin"),
        ("TERM", "xterm-256color"),
        ("LANG", "C.UTF-8"),
        ("TMPDIR", "/tmp"),
        ("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
        ("NIX_SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"),
    ]
    .into_iter()
    .map(|(name, value)| EnvVar {
        name: name.to_owned(),
        value: Some(value.to_owned()),
        ..Default::default()
    })
    .collect();
    let container = Container {
        name: TERMINAL_CONTAINER.to_owned(),
        image: Some(plan.image.clone()),
        // Exec starts the agent inside this tmux server.
        command: Some(vec![
            plan.tmux.clone(),
            "-S".to_owned(),
            TERMINAL_SOCKET.to_owned(),
            "-f".to_owned(),
            "/dev/null".to_owned(),
            "-D".to_owned(),
        ]),
        working_dir: Some(plan.workspace.clone()),
        env: Some(env),
        volume_mounts: Some(mounts),
        resources: Some(ResourceRequirements {
            requests: Some(BTreeMap::from([
                ("cpu".to_owned(), Quantity("250m".to_owned())),
                ("memory".to_owned(), Quantity("512Mi".to_owned())),
            ])),
            limits: Some(BTreeMap::from([(
                "memory".to_owned(),
                Quantity("4Gi".to_owned()),
            )])),
            ..Default::default()
        }),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_owned()]),
                add: None,
            }),
            run_as_non_root: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    Pod {
        metadata: ObjectMeta {
            name: Some(terminal_pod_name(&plan.run_id)),
            labels: Some(labels(plan)),
            ..Default::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Never".to_owned()),
            automount_service_account_token: Some(false),
            enable_service_links: Some(false),
            termination_grace_period_seconds: Some(10),
            containers: vec![container],
            volumes: Some(volumes),
            security_context: Some(PodSecurityContext {
                run_as_non_root: Some(true),
                run_as_user: Some(plan.uid),
                run_as_group: Some(plan.gid),
                seccomp_profile: Some(SeccompProfile {
                    type_: "RuntimeDefault".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            affinity: Some(Affinity {
                node_affinity: Some(NodeAffinity {
                    required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                        node_selector_terms: vec![NodeSelectorTerm {
                            match_fields: Some(vec![NodeSelectorRequirement {
                                key: "metadata.name".to_owned(),
                                operator: "In".to_owned(),
                                values: Some(vec![plan.node.clone()]),
                            }]),
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn phase(pod: &Pod) -> Option<&str> {
    pod.status.as_ref()?.phase.as_deref()
}

fn ready(pod: &Pod) -> bool {
    phase(pod) == Some("Running")
        && pod
            .status
            .as_ref()
            .and_then(|status| status.container_statuses.as_ref())
            .is_some_and(|statuses| statuses.iter().all(|status| status.ready))
}

pub fn terminal_correlation(session: &str) -> Result<CorrelationId, KubeError> {
    CorrelationId::new(&session.replace('-', ""))
        .map_err(|error| KubeError::rejected(error.to_string()))
}

pub async fn ensure_terminal_pod(
    client: &KubeClient,
    stops: &StopAuthority,
    cluster: &str,
    namespace: &str,
    plan: &TerminalPodPlan,
) -> Result<String, KubeError> {
    let correlation = terminal_correlation(&plan.session)?;
    let pinned: Vec<WorkloadGatewayTarget> = plan
        .bridge
        .iter()
        .chain(&plan.git_mirror)
        .cloned()
        .collect();
    let resolved = resolve_hosts(&plan.allow_hosts, &pinned).await?;
    let worker = odin_kernel::stop::mint_worker_id()
        .map_err(|error| KubeError::unavailable(error.to_string()))?;
    let mut identity = odin_kernel::stop::PodWorkerIdentity {
        cluster: cluster.to_owned(),
        namespace: namespace.to_owned(),
        pod_name: terminal_pod_name(&plan.run_id),
        pod_uid: None,
        policy_name: egress_policy_name(&plan.run_id),
        policy_uid: None,
        secret_name: None,
        secret_uid: None,
        correlation_id: correlation.as_str().to_owned(),
    };
    stops
        .register_pod_worker(&worker, &identity, &correlation)
        .map_err(stop_error)?;
    let mut create_timed_out = false;
    let result = async {
        let mut policy = crate::workload::desired_egress_policy(&plan.run_id, &resolved);
        label_worker(&mut policy.metadata, &worker, &correlation);
        let policy = tokio::time::timeout(
            client.request_timeout(),
            client
                .network_policies()
                .create(&PostParams::default(), &policy),
        )
        .await
        .map_err(|error| {
            create_timed_out = true;
            KubeError::unavailable(format!("create terminal policy: {error}"))
        })?
        .map_err(|error| KubeError::unavailable(format!("create terminal policy: {error}")))?;
        identity.policy_uid = policy.metadata.uid;
        stops
            .update_pod_worker_identity(&worker, &identity)
            .map_err(stop_error)?;
        let mut pod = desired_terminal_pod(plan);
        label_worker(&mut pod.metadata, &worker, &correlation);
        let pod = tokio::time::timeout(
            client.request_timeout(),
            client.pods().create(&PostParams::default(), &pod),
        )
        .await
        .map_err(|error| {
            create_timed_out = true;
            KubeError::unavailable(format!("create terminal pod: {error}"))
        })?
        .map_err(|error| KubeError::unavailable(format!("create terminal pod: {error}")))?;
        identity.pod_uid = pod.metadata.uid;
        stops
            .update_pod_worker_identity(&worker, &identity)
            .map_err(stop_error)?;
        crate::object_wait::wait_for(
            &client.pods(),
            &identity.pod_name,
            START_BOUND,
            || format!("terminal pod {} did not become ready", identity.pod_name),
            |pod| match pod {
                Some(pod) if pod.metadata.uid != identity.pod_uid => Settle::Fail(
                    KubeError::rejected("terminal pod UID changed before exposure"),
                ),
                Some(pod) if ready(pod) => Settle::Done(()),
                Some(pod) if matches!(phase(pod), Some("Succeeded" | "Failed")) => {
                    Settle::Fail(KubeError::unavailable("terminal pod ended before ready"))
                }
                _ => Settle::Wait,
            },
        )
        .await?;
        Ok(identity.pod_name)
    }
    .await;
    if let Err(error) = &result {
        if create_timed_out {
            // A timed-out create can still commit after an immediate cleanup read.
            tracing::warn!(
                "create terminal pod worker={worker} failed: {error}; ledger cleanup retained"
            );
            return result;
        }
        if let Err(error) = stops.stop_pod_worker(&worker) {
            tracing::warn!("stop terminal pod worker={worker} failed: {error}");
        }
    }
    result
}

pub(crate) fn label_worker(
    metadata: &mut ObjectMeta,
    worker: &WorkerId,
    correlation: &CorrelationId,
) {
    let annotations = metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert(WORKER_ANNOTATION.to_owned(), worker.as_str().to_owned());
    annotations.insert(
        CORRELATION_ANNOTATION.to_owned(),
        correlation.as_str().to_owned(),
    );
}

pub(crate) fn stop_error(error: odin_kernel::stop::StopAuthorityError) -> KubeError {
    KubeError::Storage {
        reason: format!("pod ledger operation failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> TerminalPodPlan {
        TerminalPodPlan {
            run_id: RunId::new("run:live:0f1e2d3c-0000-4000-8000-000000000001").expect("run"),
            session: "0f1e2d3c-0000-4000-8000-000000000001".to_owned(),
            image: "localhost/odin-workload@sha256:abc".to_owned(),
            node: "mini".to_owned(),
            uid: 1000,
            gid: 100,
            home: "/home/colin".to_owned(),
            workspace: "/home/colin/valhalla/.odin-workspaces/s1".to_owned(),
            runtime: Some("/home/colin/.local/state/odin-term/0f1e2d3c".to_owned()),
            credentials: vec![
                "/home/colin/.claude".to_owned(),
                "/home/colin/.claude.json".to_owned(),
            ],
            tmux: "/odin/bin/tmux".to_owned(),
            allow_hosts: vec!["api.anthropic.com".to_owned()],
            bridge: None,
            git_mirror: None,
        }
    }

    #[test]
    fn terminal_correlation_matches_session_for_launch_and_stop() {
        let plan = plan();
        let launch = terminal_correlation(&plan.session).expect("launch correlation");
        let stop =
            terminal_correlation("0f1e2d3c-0000-4000-8000-000000000001").expect("stop correlation");
        assert_eq!(launch, stop);
        assert_eq!(launch.as_str(), "0f1e2d3c000040008000000000000001");
        assert!(terminal_correlation(plan.run_id.as_str()).is_err());
    }

    #[test]
    fn the_terminal_pod_mounts_only_what_is_declared_at_its_own_paths() {
        let plan = plan();
        let pod = desired_terminal_pod(&plan);
        let spec = pod.spec.as_ref().expect("spec");
        assert!(spec.scheduling_gates.is_none());
        let container = &spec.containers[0];
        assert_eq!(container.name, TERMINAL_CONTAINER);
        assert_eq!(
            container.command.as_deref().expect("command")[..3],
            ["/odin/bin/tmux", "-S", TERMINAL_SOCKET]
        );
        assert_eq!(
            container.working_dir.as_deref(),
            Some(plan.workspace.as_str())
        );
        let mounts: Vec<(String, bool)> = container
            .volume_mounts
            .as_ref()
            .expect("mounts")
            .iter()
            .map(|mount| (mount.mount_path.clone(), mount.read_only.unwrap_or(false)))
            .collect();
        assert_eq!(
            mounts,
            [
                ("/home/colin".to_owned(), false),
                ("/run/odin-term".to_owned(), false),
                (plan.workspace.clone(), false),
                (
                    "/home/colin/.local/state/odin-term/0f1e2d3c".to_owned(),
                    true
                ),
                ("/home/colin/.claude".to_owned(), false),
                ("/home/colin/.claude.json".to_owned(), false),
            ]
        );
        let host_paths: Vec<(&str, Option<&str>)> = spec
            .volumes
            .as_ref()
            .expect("volumes")
            .iter()
            .filter_map(|volume| {
                volume
                    .host_path
                    .as_ref()
                    .map(|path| (path.path.as_str(), path.type_.as_deref()))
            })
            .collect();
        assert_eq!(
            host_paths[2..],
            [
                ("/home/colin/.claude", Some("Directory")),
                ("/home/colin/.claude.json", Some("File"))
            ],
            "the account login: its directory and its account record file"
        );
        let security = spec.security_context.as_ref().expect("pod security");
        assert_eq!(security.run_as_user, Some(1000));
        assert_eq!(security.run_as_non_root, Some(true));
        let container_security = container.security_context.as_ref().expect("security");
        assert_eq!(container_security.allow_privilege_escalation, Some(false));
        assert_eq!(spec.automount_service_account_token, Some(false));
        let labels = pod.metadata.labels.as_ref().expect("labels");
        assert_eq!(
            labels.get(JOB_LABEL_RUN_ID).map(String::as_str),
            Some(bounded_label_value(plan.run_id.as_str()).as_str())
        );
        let node = spec
            .affinity
            .as_ref()
            .and_then(|affinity| affinity.node_affinity.as_ref())
            .and_then(|affinity| {
                affinity
                    .required_during_scheduling_ignored_during_execution
                    .as_ref()
            })
            .map(|selector| selector.node_selector_terms[0].clone())
            .and_then(|term| term.match_fields)
            .expect("node affinity");
        assert_eq!(node[0].values.as_deref(), Some(&["mini".to_owned()][..]));
    }

    #[test]
    fn no_credential_means_no_credential_mount() {
        let mut plan = plan();
        plan.credentials.clear();
        plan.runtime = None;
        let pod = desired_terminal_pod(&plan);
        let volumes = pod.spec.expect("spec").volumes.expect("volumes");
        assert_eq!(
            volumes
                .iter()
                .filter(|volume| volume.host_path.is_some())
                .count(),
            1,
            "only the workspace"
        );
        assert_eq!(
            terminal_pod_name(&plan.run_id),
            terminal_pod_name(&plan.run_id),
            "stable for a reclaim"
        );
    }
}
