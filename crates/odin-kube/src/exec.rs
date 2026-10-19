//! UID-verified exec transport for workload run carriers.
//!
//! The pod stays alive without starting the launcher until exec attaches,
//! so startup frames cannot precede the consumer. Exec verifies the pod's
//! owner reference against the Job UID and targets a named container.
//! The trusted runtime supplies the pinned launcher and arguments, not the model.
//! Kubernetes exec cannot set environment variables; use the RPC handshake
//! or the launch configuration instead.
//!
//! Closing exec does not stop the pod; recreation still requires an authorized stop.
//! Graceful bridge stop closes stdin, drains EOF, then takes the remote exit status.

use k8s_openapi::api::core::v1::Pod;
use kube::api::{AttachParams, AttachedProcess};
use odin_domain::RunId;
use odin_registry::schema::valid_pod_path;

use crate::client::{KubeClient, KubeError};
use crate::job::{job_name, JOB_WORKER_CONTAINER};
use crate::workload::WORKLOAD_LABEL;

use crate::workload::placement;

/// Composed by the trusted runtime from the profile's pinned launcher and
/// RPC/model arguments, never model input. The launcher path must be absolute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadLauncherSpec {
    pub launcher_path: String,
    pub arguments: Vec<String>,
}

impl WorkloadLauncherSpec {
    /// The argv actually executed: pinned launcher first, then arguments.
    /// `Err` carries the typed reason the composition is not executable.
    pub fn argv(&self) -> Result<Vec<String>, WorkloadExecError> {
        if !valid_pod_path(&self.launcher_path) {
            return Err(WorkloadExecError::Foreign {
                reason: format!(
                    "launcher path {:?} is not an absolute in-image path",
                    self.launcher_path
                ),
            });
        }
        if self.arguments.iter().any(String::is_empty) {
            return Err(WorkloadExecError::EmptyCommand);
        }
        let mut argv = Vec::with_capacity(1 + self.arguments.len());
        argv.push(self.launcher_path.clone());
        argv.extend(self.arguments.iter().cloned());
        Ok(argv)
    }
}
/// The typed exec target container of one carrier attach: explicit at
/// every call site — never a default, never a discovered first container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobExecTarget {
    /// The model/agent worker container every carrier pod runs.
    Worker,
    /// The dedicated browser container workload pods run for the relay.
    Browser,
}

impl JobExecTarget {
    fn container_name(self) -> &'static str {
        match self {
            JobExecTarget::Worker => JOB_WORKER_CONTAINER,
            JobExecTarget::Browser => crate::workload::BROWSER_CONTAINER,
        }
    }
}

/// Attach failures are returned without retrying.
#[derive(Clone, Debug, thiserror::Error)]
pub enum WorkloadExecError {
    /// The run's Job is absent from the API server.
    #[error("workload carrier is gone: {reason}")]
    Gone { reason: String },
    /// The carrier pod exists but is not Running, or no pod exists yet.
    #[error("workload carrier is not running")]
    NotRunning { pod: String, phase: Option<String> },
    /// The pod, Job binding, or launcher path does not match the admitted workload.
    #[error("workload carrier is foreign: {reason}")]
    Foreign { reason: String },
    /// The exec attach itself failed or timed out.
    #[error("workload exec attach failed: {reason}")]
    AttachFailed { reason: String },
    /// The host-composed command carried empty elements.
    #[error("workload exec command carries empty elements")]
    EmptyCommand,
}

/// Close stdin, drain EOF, and take remote status for a graceful bridge stop.
pub struct WorkloadExecChannel {
    pub pod: String,
    /// The kube exec transport: stdin/stdout/stderr plus remote status.
    pub process: AttachedProcess,
}

/// Identity and container checks use the same fetched Pod object.
struct ResolvedCarrier {
    pod: String,
}

/// Verifies the Job's projection and labels, then resolves a Running pod
/// whose owner reference matches that Job's UID.
async fn resolve_carrier(
    client: &KubeClient,
    run_id: &RunId,
    target: JobExecTarget,
) -> Result<ResolvedCarrier, WorkloadExecError> {
    let name = job_name(run_id);
    let job = client
        .jobs()
        .get_opt(&name)
        .await
        .map_err(|error| WorkloadExecError::Gone {
            reason: error.to_string(),
        })?
        .ok_or_else(|| WorkloadExecError::Gone {
            reason: format!("owned Job {name} is absent from the API server"),
        })?;
    // Validate all eleven labels and the annotation's Job UID before attaching.
    crate::status::observe_job(&client.config.cluster, &job, 0).map_err(|error| {
        WorkloadExecError::Foreign {
            reason: format!("Job {name} is not an Odin-owned workload: {error}"),
        }
    })?;
    let job_uid = job
        .metadata
        .uid
        .clone()
        .ok_or_else(|| WorkloadExecError::Foreign {
            reason: format!("Job {name} carries no API UID"),
        })?;
    let found = placement(client, run_id)
        .await
        .map_err(|error| match &error {
            KubeError::Rejected { reason } => WorkloadExecError::Foreign {
                reason: reason.clone(),
            },
            _ => WorkloadExecError::AttachFailed {
                reason: error.to_string(),
            },
        })?
        .ok_or_else(|| WorkloadExecError::NotRunning {
            pod: name.clone(),
            phase: None,
        })?;
    if found.phase.as_deref() != Some("Running") {
        return Err(WorkloadExecError::NotRunning {
            pod: found.pod,
            phase: found.phase,
        });
    }
    let pod: Pod = client
        .pods()
        .get_opt(&found.pod)
        .await
        .map_err(|error| WorkloadExecError::AttachFailed {
            reason: error.to_string(),
        })?
        .ok_or_else(|| WorkloadExecError::Gone {
            reason: format!("carrier pod {} disappeared before attach", found.pod),
        })?;
    let owned = pod.metadata.owner_references.as_ref().is_some_and(|refs| {
        refs.iter()
            .any(|reference| reference.kind == "Job" && reference.uid == job_uid)
    });
    if !owned {
        return Err(WorkloadExecError::Foreign {
            reason: format!("pod {} is not owned by Job UID {job_uid}", found.pod),
        });
    }
    if target == JobExecTarget::Browser {
        browser_container_verdict(&pod, &found.pod)?;
    }
    Ok(ResolvedCarrier { pod: found.pod })
}

/// Check the workload label and running browser container on the same Pod
/// used for the owner-reference check.
fn browser_container_verdict(pod: &Pod, pod_name: &str) -> Result<(), WorkloadExecError> {
    let workload_bound = pod
        .metadata
        .labels
        .as_ref()
        .is_some_and(|labels| labels.contains_key(crate::workload::WORKLOAD_LABEL));
    if !workload_bound {
        return Err(WorkloadExecError::Foreign {
            reason: format!(
                "pod {pod_name} carries no {WORKLOAD_LABEL} binding: the browser relay attaches only to workload carriers"
            ),
        });
    }
    // The browser runs as a native sidecar (an init container restarting
    // Always); pods created before that change declare it as a regular
    // container, and both shapes are the same proven browser.
    let declared = pod.spec.as_ref().is_some_and(|spec| {
        spec.containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
            .any(|container| container.name == crate::workload::BROWSER_CONTAINER)
    });
    if !declared {
        return Err(WorkloadExecError::Foreign {
            reason: format!("carrier pod {pod_name} declares no browser container"),
        });
    }
    let running = pod
        .status
        .as_ref()
        .and_then(|status| {
            status
                .container_statuses
                .iter()
                .flatten()
                .chain(status.init_container_statuses.iter().flatten())
                .find(|status| status.name == crate::workload::BROWSER_CONTAINER)
        })
        .and_then(|status| status.state.as_ref())
        .is_some_and(|state| state.running.is_some());
    if !running {
        return Err(WorkloadExecError::NotRunning {
            pod: pod_name.to_owned(),
            phase: None,
        });
    }
    Ok(())
}

/// One attached exec channel decomposed into type-erased halves, ready to
/// wrap into a transport-agnostic remote harness channel. The kube types
/// stay inside this crate; consumers depend only on these aliases.
pub struct WorkloadExecStream {
    pub pod: String,
    pub stdin: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    pub stdout: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    pub stderr: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    /// `Some(reason)` reports an unclean end; `None` reports clean exit.
    /// Dropping the future aborts the attach pump, but does not stop the pod.
    pub exit: std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>>,
}

/// Missing stdin or stdout fails the attach; stderr is optional.
/// The returned exit future keeps the attach pump alive until status or cancellation.
pub fn decompose(mut channel: WorkloadExecChannel) -> Result<WorkloadExecStream, KubeError> {
    let stdin = channel
        .process
        .stdin()
        .map(|writer| Box::new(writer) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>)
        .ok_or_else(|| attach_missing("stdin"))?;
    let stdout = channel
        .process
        .stdout()
        .map(|reader| Box::new(reader) as Box<dyn tokio::io::AsyncRead + Unpin + Send>)
        .ok_or_else(|| attach_missing("stdout"))?;
    let stderr = channel
        .process
        .stderr()
        .map(|reader| Box::new(reader) as Box<dyn tokio::io::AsyncRead + Unpin + Send>);
    let status = channel.process.take_status();
    let shell = channel.process;

    // Keep the pump alive while waiting; dropping the future aborts it.
    let exit = Box::pin(async move {
        let _shell = shell;
        match status {
            Some(mut status_fut) => {
                let outcome = (&mut status_fut).await;
                match outcome {
                    Some(status) => {
                        let clean = status.status.as_deref() == Some("Success");
                        (!clean).then(|| {
                            status.message.or(status.reason).unwrap_or_else(|| {
                                "carrier exited without a Success status".to_owned()
                            })
                        })
                    }
                    None => Some("carrier status channel closed without a verdict".to_owned()),
                }
            }
            None => Some("the carrier carries no status channel".to_owned()),
        }
    });

    Ok(WorkloadExecStream {
        pod: channel.pod,
        stdin,
        stdout,
        stderr,
        exit,
    })
}

fn attach_missing(half: &str) -> KubeError {
    KubeError::Unavailable {
        reason: format!("the exec attach opened without its {half} half"),
    }
}

/// Starts the launcher only after attach, so startup frames cannot precede
/// the consumer. Streams support the RPC handshake and graceful shutdown.
pub async fn exec_fixed(
    client: &KubeClient,
    run_id: &RunId,
    target: JobExecTarget,
    launcher: &WorkloadLauncherSpec,
) -> Result<WorkloadExecChannel, WorkloadExecError> {
    let argv = launcher.argv()?;
    let carrier = resolve_carrier(client, run_id, target).await?;
    let pod = carrier.pod;
    let params = AttachParams {
        stdin: true,
        stdout: true,
        stderr: true,
        tty: false,
        ..AttachParams::default()
    }
    .container(target.container_name());
    let process = tokio::time::timeout(
        client.request_timeout(),
        client.pods().exec(&pod, argv, &params),
    )
    .await
    .map_err(|_| WorkloadExecError::AttachFailed {
        reason: "the exec attach timed out".to_owned(),
    })?
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: error.to_string(),
    })?;
    Ok(WorkloadExecChannel { pod, process })
}

/// The finished carrier's release argv: the pod-level stop (`SIGTERM`) to
/// the worker container's PID 1, the passive `odind workload-park` carrier,
/// which handles exactly that signal with a clean exit. Run through the
/// image's own coreutils `kill` (`/bin` holds coreutils in every workload
/// image); never a shell.
pub const CARRIER_RELEASE_ARGV: [&str; 3] = ["/bin/kill", "-TERM", "1"];

/// Release a finished session's parked carrier with SIGTERM so its worker
/// exits cleanly and the Job can complete, rather than deleting the Job.
/// Uses the same identity checks as attach and waits for the worker to exit.
pub async fn release_carrier(
    client: &KubeClient,
    run_id: &RunId,
) -> Result<String, WorkloadExecError> {
    let carrier = resolve_carrier(client, run_id, JobExecTarget::Worker).await?;
    let params = AttachParams {
        stdin: false,
        stdout: true,
        stderr: true,
        tty: false,
        ..AttachParams::default()
    }
    .container(JobExecTarget::Worker.container_name());
    let mut process = tokio::time::timeout(
        client.request_timeout(),
        client
            .pods()
            .exec(&carrier.pod, CARRIER_RELEASE_ARGV, &params),
    )
    .await
    .map_err(|_| WorkloadExecError::AttachFailed {
        reason: "the carrier release exec timed out".to_owned(),
    })?
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: error.to_string(),
    })?;
    let status = process.take_status();
    let verdict = match status {
        Some(status) => tokio::time::timeout(client.request_timeout(), status)
            .await
            .map_err(|_| WorkloadExecError::AttachFailed {
                reason: "the carrier release exec never reported its status".to_owned(),
            })?,
        None => None,
    };
    match verdict {
        Some(status) if status.status.as_deref() == Some("Success") => {}
        other => {
            return Err(WorkloadExecError::AttachFailed {
                reason: format!(
                    "the carrier release exec did not succeed: {}",
                    other
                        .and_then(|status| status.message)
                        .unwrap_or_else(|| "no status".to_owned())
                ),
            })
        }
    }
    // A delivered SIGTERM is not an exit: the worker container must stop.
    crate::object_wait::wait_for(
        &client.pods(),
        &carrier.pod,
        client.teardown_timeout(),
        || {
            format!(
                "the carrier in pod {} did not exit after SIGTERM",
                carrier.pod
            )
        },
        |pod| match pod {
            Some(pod) if !carrier_exited(pod) => crate::object_wait::Settle::Wait,
            _ => crate::object_wait::Settle::Done(()),
        },
    )
    .await
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: error.to_string(),
    })?;
    Ok(carrier.pod)
}

/// The pod finished, or its worker container has terminated.
fn carrier_exited(pod: &Pod) -> bool {
    let status = pod.status.as_ref();
    matches!(
        status.and_then(|status| status.phase.as_deref()),
        Some("Succeeded" | "Failed")
    ) || status
        .and_then(|status| status.container_statuses.as_ref())
        .into_iter()
        .flatten()
        .any(|container| {
            container.name == JobExecTarget::Worker.container_name()
                && container
                    .state
                    .as_ref()
                    .is_some_and(|state| state.terminated.is_some())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signalled_carrier_counts_as_released_only_once_it_exits() {
        let pod = |phase: &str, worker: serde_json::Value| -> Pod {
            serde_json::from_value(serde_json::json!({
                "metadata": {"name": "p"},
                "status": {"phase": phase, "containerStatuses": [{
                    "name": JobExecTarget::Worker.container_name(),
                    "image": "i", "imageID": "", "ready": true, "restartCount": 0, "state": worker,
                }]},
            }))
            .expect("pod fixture")
        };
        assert!(!carrier_exited(&pod(
            "Running",
            serde_json::json!({"running": {}})
        )));
        assert!(carrier_exited(&pod(
            "Running",
            serde_json::json!({"terminated": {"exitCode": 0}})
        )));
        assert!(carrier_exited(&pod(
            "Succeeded",
            serde_json::json!({"running": {}})
        )));
    }

    #[test]
    fn a_terminated_sidecar_does_not_release_the_carrier() {
        let status = |name: &str, state: serde_json::Value| {
            serde_json::json!({
                "name": name,
                "image": "i",
                "imageID": "",
                "ready": false,
                "restartCount": 0,
                "state": state,
            })
        };
        let pod = |phase: &str, statuses: serde_json::Value| -> Pod {
            serde_json::from_value(serde_json::json!({
                "metadata": {"name": "p"},
                "status": {"phase": phase, "containerStatuses": statuses},
            }))
            .expect("pod fixture")
        };
        let worker = JobExecTarget::Worker.container_name();
        assert!(
            !carrier_exited(&pod(
                "Running",
                serde_json::json!([
                    status(worker, serde_json::json!({"running": {}})),
                    status(
                        "sidecar",
                        serde_json::json!({"terminated": {"exitCode": 0}})
                    ),
                ])
            )),
            "a terminated non-worker does not release the carrier"
        );
        assert!(
            carrier_exited(&pod(
                "Failed",
                serde_json::json!([status(worker, serde_json::json!({"running": {}}))])
            )),
            "Failed phase releases even while the worker is running"
        );
        let bare: Pod = serde_json::from_value(serde_json::json!({
            "metadata": {"name": "p"},
            "status": {"phase": "Running"},
        }))
        .expect("pod fixture");
        assert!(
            !carrier_exited(&bare),
            "Running with no container statuses is not an exit"
        );
    }

    fn workload_pod(with_label: bool, with_browser: bool, browser_running: bool) -> Pod {
        let mut labels = std::collections::BTreeMap::new();
        if with_label {
            labels.insert(
                crate::workload::WORKLOAD_LABEL.to_owned(),
                "continuity-fixture".to_owned(),
            );
        }
        let mut containers = vec![k8s_openapi::api::core::v1::Container {
            name: JOB_WORKER_CONTAINER.to_owned(),
            ..Default::default()
        }];
        if with_browser {
            containers.push(k8s_openapi::api::core::v1::Container {
                name: crate::workload::BROWSER_CONTAINER.to_owned(),
                ..Default::default()
            });
        }
        let container_statuses = with_browser.then(|| {
            vec![k8s_openapi::api::core::v1::ContainerStatus {
                name: crate::workload::BROWSER_CONTAINER.to_owned(),
                state: Some(k8s_openapi::api::core::v1::ContainerState {
                    running: (browser_running)
                        .then(k8s_openapi::api::core::v1::ContainerStateRunning::default),
                    ..Default::default()
                }),
                ..Default::default()
            }]
        });
        Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::PodSpec {
                containers,
                ..Default::default()
            }),
            status: container_statuses.map(|statuses| k8s_openapi::api::core::v1::PodStatus {
                container_statuses: Some(statuses),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn the_browser_verdict_accepts_a_running_browser_container_on_a_workload_pod() {
        let pod = workload_pod(true, true, true);
        assert!(browser_container_verdict(&pod, "probe-pod").is_ok());
    }

    /// Native sidecars declare their status under `initContainerStatuses`.
    #[test]
    fn the_browser_verdict_accepts_a_running_browser_sidecar() {
        let mut pod = workload_pod(true, true, true);
        let spec = pod.spec.as_mut().expect("spec");
        let browser = spec.containers.pop().expect("browser");
        spec.init_containers = Some(vec![k8s_openapi::api::core::v1::Container {
            restart_policy: Some("Always".to_owned()),
            ..browser
        }]);
        let status = pod.status.as_mut().expect("status");
        status.init_container_statuses = status.container_statuses.take();
        assert!(browser_container_verdict(&pod, "probe-pod").is_ok());
        pod.status
            .as_mut()
            .expect("status")
            .init_container_statuses
            .as_mut()
            .expect("statuses")[0]
            .state = Some(k8s_openapi::api::core::v1::ContainerState::default());
        assert!(matches!(
            browser_container_verdict(&pod, "probe-pod"),
            Err(WorkloadExecError::NotRunning { .. })
        ));
    }

    #[test]
    fn the_carrier_release_is_the_pod_level_stop_to_pid_one() {
        assert_eq!(CARRIER_RELEASE_ARGV, ["/bin/kill", "-TERM", "1"]);
        assert!(valid_pod_path(CARRIER_RELEASE_ARGV[0]));
    }

    #[test]
    fn the_browser_verdict_refuses_a_pod_without_the_workload_binding() {
        let pod = workload_pod(false, true, true);
        let error = browser_container_verdict(&pod, "probe-pod").expect_err("foreign pod");
        assert!(
            matches!(error, WorkloadExecError::Foreign { .. }),
            "a non-workload pod is foreign: {error:?}"
        );
    }

    #[test]
    fn the_browser_verdict_refuses_a_pod_that_declares_no_browser_container() {
        let pod = workload_pod(true, false, false);
        let error = browser_container_verdict(&pod, "probe-pod").expect_err("missing browser");
        assert!(
            matches!(error, WorkloadExecError::Foreign { .. }),
            "a missing browser container is a foreign pod shape: {error:?}"
        );
    }

    #[test]
    fn the_browser_verdict_refuses_a_terminated_browser_container() {
        let pod = workload_pod(true, true, false);
        let error = browser_container_verdict(&pod, "probe-pod").expect_err("terminated browser");
        assert!(
            matches!(error, WorkloadExecError::NotRunning { .. }),
            "a terminated browser container is not attachable: {error:?}"
        );
    }

    #[test]
    fn launcher_spec_law_rejects_relative_paths_and_blank_arguments() {
        let relative = WorkloadLauncherSpec {
            launcher_path: "odin/bin/omp".to_owned(),
            arguments: vec!["--mode".to_owned(), "rpc".to_owned()],
        };
        assert!(matches!(
            relative.argv(),
            Err(WorkloadExecError::Foreign { .. })
        ));
        let blank = WorkloadLauncherSpec {
            launcher_path: "/odin/bin/omp".to_owned(),
            arguments: vec![String::new()],
        };
        assert!(matches!(blank.argv(), Err(WorkloadExecError::EmptyCommand)));
        let lawful = WorkloadLauncherSpec {
            launcher_path: "/odin/bin/omp".to_owned(),
            arguments: vec!["--mode".to_owned(), "rpc".to_owned()],
        };
        assert_eq!(
            lawful.argv().expect("lawful spec"),
            vec![
                "/odin/bin/omp".to_owned(),
                "--mode".to_owned(),
                "rpc".to_owned()
            ]
        );
    }
}
