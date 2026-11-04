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
use crate::workload::{placement, WORKLOAD_LABEL};

/// Attach's defaults are 1 KiB duplexes: parallel RPC frames can fill stdout
/// while one result exceeds stdin, deadlocking the single attach message loop.
const ATTACH_BUFFER_BYTES: usize = 1024 * 1024;

fn attach_params(stdin: bool) -> AttachParams {
    AttachParams {
        stdin,
        stdout: true,
        stderr: true,
        tty: false,
        max_stdin_buf_size: Some(ATTACH_BUFFER_BYTES),
        max_stdout_buf_size: Some(ATTACH_BUFFER_BYTES),
        max_stderr_buf_size: Some(ATTACH_BUFFER_BYTES),
        ..AttachParams::default()
    }
}

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
    job_uid: String,
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
    Ok(ResolvedCarrier {
        pod: found.pod,
        job_uid,
    })
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
    let params = attach_params(true).container(target.container_name());
    let process = tokio::time::timeout(
        client.request_timeout(),
        client.pods().exec(&pod, argv, &params),
    )
    .await
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: format!("the exec attach timed out: {error}"),
    })?
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: error.to_string(),
    })?;
    Ok(WorkloadExecChannel { pod, process })
}

/// One fixed argv run to its end in a carrier's worker container: its exit
/// code and the last bytes of each stream, with each stream's full length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRun {
    pub exit_code: i32,
    pub stdout_tail: Vec<u8>,
    pub stderr_tail: Vec<u8>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

/// The worker image's `head`, which hands a command exactly the stdin bytes it was given.
const WORKER_HEAD: &str = "/bin/head";
const WORKER_SH: &str = "/bin/sh";

/// `argv` reading exactly `bytes` of stdin: `head -c` ends the command's input after that
/// count, so its end never rides the exec stream's stdin close. kube-rs sends that close right
/// behind the last 4 KiB stdin frame and the close can win, which cut every write into a pod to
/// a 4 KiB multiple. The argv stays positional parameters, never shell text.
fn bounded_stdin(argv: &[String], bytes: usize) -> Vec<String> {
    let mut bounded = vec![
        WORKER_SH.to_owned(),
        "-c".to_owned(),
        format!("{WORKER_HEAD} -c \"$0\" | \"$@\""),
        bytes.to_string(),
    ];
    bounded.extend(argv.iter().cloned());
    bounded
}

/// Runs `argv` in the worker container of `run_id` (no shell), given exactly
/// `stdin` when present, and waits at most `wait` for it to end, keeping
/// `tail_bytes` of each stream. Stdin stays open until the command exits; a
/// command short of its bytes waits out `wait` and fails rather than reading
/// a cut input. A run that outlives `wait` is abandoned, not reported as done.
pub async fn run_in_worker(
    client: &KubeClient,
    run_id: &RunId,
    argv: &[String],
    stdin: Option<&[u8]>,
    wait: std::time::Duration,
    tail_bytes: usize,
) -> Result<WorkerRun, WorkloadExecError> {
    if argv.is_empty() || argv.iter().any(String::is_empty) {
        return Err(WorkloadExecError::EmptyCommand);
    }
    let carrier = resolve_carrier(client, run_id, JobExecTarget::Worker).await?;
    let params = attach_params(stdin.is_some()).container(JobExecTarget::Worker.container_name());
    let argv = match stdin {
        Some(bytes) => bounded_stdin(argv, bytes.len()),
        None => argv.to_vec(),
    };
    let mut process = tokio::time::timeout(
        client.request_timeout(),
        client.pods().exec(&carrier.pod, argv, &params),
    )
    .await
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: format!("the exec attach timed out: {error}"),
    })?
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: error.to_string(),
    })?;
    let writer = process.stdin();
    let stdout = process.stdout();
    let stderr = process.stderr();
    let status = process.take_status();
    let finished = tokio::time::timeout(wait, async move {
        // The writer is returned, not dropped: dropping it closes the remote
        // stdin, which must wait until the command has exited.
        let feed = async move {
            match (writer, stdin) {
                (Some(mut writer), Some(bytes)) => {
                    use tokio::io::AsyncWriteExt;
                    writer.write_all(bytes).await?;
                    writer.flush().await?;
                    Ok::<_, std::io::Error>(Some(writer))
                }
                _ => Ok(None),
            }
        };
        let (fed, stdout, stderr) = tokio::join!(
            feed,
            read_tail(stdout, tail_bytes),
            read_tail(stderr, tail_bytes)
        );
        let status = match status {
            Some(status) => status.await,
            None => None,
        };
        (fed, stdout, stderr, status)
    })
    .await
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: format!("the exec did not end within {} s: {error}", wait.as_secs()),
    })?;
    let (fed, (stdout_tail, stdout_bytes), (stderr_tail, stderr_bytes), status) = finished;
    let exit_code = exit_code(status.as_ref())?;
    // A command that failed says why on stderr; one that succeeded on a
    // cut-short stdin did not get what it was given.
    if let (Err(error), 0) = (fed, exit_code) {
        return Err(WorkloadExecError::AttachFailed {
            reason: format!("its stdin could not be written whole: {error}"),
        });
    }
    Ok(WorkerRun {
        exit_code,
        stdout_tail,
        stderr_tail,
        stdout_bytes,
        stderr_bytes,
    })
}

/// Reads a stream to its end, keeping its last `keep` bytes and its length.
async fn read_tail(
    stream: Option<impl tokio::io::AsyncRead + Unpin>,
    keep: usize,
) -> (Vec<u8>, u64) {
    use tokio::io::AsyncReadExt;
    let mut tail = Vec::new();
    let mut total = 0u64;
    let Some(mut stream) = stream else {
        return (tail, total);
    };
    let mut buffer = [0u8; 8192];
    while let Ok(read) = stream.read(&mut buffer).await {
        if read == 0 {
            break;
        }
        total += read as u64;
        tail.extend_from_slice(&buffer[..read]);
        if tail.len() > keep {
            tail.drain(..tail.len() - keep);
        }
    }
    (tail, total)
}

/// The exit code a kube exec status reports: `Success` is 0, and a
/// non-zero exit carries its code as the `ExitCode` cause.
fn exit_code(
    status: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>,
) -> Result<i32, WorkloadExecError> {
    let Some(status) = status else {
        return Err(WorkloadExecError::AttachFailed {
            reason: "the exec ended without reporting a status".to_owned(),
        });
    };
    if status.status.as_deref() == Some("Success") {
        return Ok(0);
    }
    status
        .details
        .as_ref()
        .and_then(|details| details.causes.as_ref())
        .into_iter()
        .flatten()
        .find(|cause| cause.reason.as_deref() == Some("ExitCode"))
        .and_then(|cause| cause.message.as_deref()?.parse().ok())
        .ok_or_else(|| WorkloadExecError::AttachFailed {
            reason: format!(
                "the exec failed without an exit code: {}",
                status.message.as_deref().unwrap_or("no message")
            ),
        })
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
    expected_job_uid: &str,
) -> Result<String, WorkloadExecError> {
    let carrier = resolve_carrier(client, run_id, JobExecTarget::Worker).await?;
    if carrier.job_uid != expected_job_uid {
        return Err(WorkloadExecError::Foreign {
            reason: "carrier release Job UID differs from the admitted incarnation".to_owned(),
        });
    }
    let params = attach_params(false).container(JobExecTarget::Worker.container_name());
    let mut process = tokio::time::timeout(
        client.request_timeout(),
        client
            .pods()
            .exec(&carrier.pod, CARRIER_RELEASE_ARGV, &params),
    )
    .await
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: format!("the carrier release exec timed out: {error}"),
    })?
    .map_err(|error| WorkloadExecError::AttachFailed {
        reason: error.to_string(),
    })?;
    let status = process.take_status();
    let verdict = match status {
        Some(status) => tokio::time::timeout(client.request_timeout(), status)
            .await
            .map_err(|error| WorkloadExecError::AttachFailed {
                reason: format!("the carrier release exec never reported its status: {error}"),
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

    /// The bounded argv run by a local shell (the host's `head`, not the image path): the
    /// command gets every byte and ends while stdin is still open, and argv stays literal.
    #[test]
    fn a_bounded_write_lands_whole_without_closing_stdin() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let payload: Vec<u8> = (0..300_000_u32).map(|i| (i % 251) as u8).collect();
        let argv = [
            "sh".to_owned(),
            "-c".to_owned(),
            "wc -c; printf '%s|' \"$@\"".to_owned(),
            "count".to_owned(),
            "a b".to_owned(),
            "$(echo no)".to_owned(),
        ];
        let mut bounded = bounded_stdin(&argv, payload.len());
        bounded[2] = bounded[2].replace(WORKER_HEAD, "head");
        let mut child = Command::new(&bounded[0])
            .args(&bounded[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn the bounded argv");
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&payload).expect("write the payload");
        stdin.flush().expect("flush");
        let output = child
            .wait_with_output()
            .expect("the command ends on its own");
        drop(stdin);
        let stdout = String::from_utf8(output.stdout).expect("utf-8");
        assert!(output.status.success());
        assert_eq!(stdout, "300000\na b|$(echo no)|");
    }

    #[tokio::test]
    async fn parallel_rpc_frames_do_not_cross_deadlock_the_attach_buffers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let params = attach_params(true);
        assert_eq!(params.max_stdin_buf_size, Some(ATTACH_BUFFER_BYTES));
        assert_eq!(params.max_stdout_buf_size, Some(ATTACH_BUFFER_BYTES));
        assert_eq!(params.max_stderr_buf_size, Some(ATTACH_BUFFER_BYTES));
        let (mut result_reader, mut result_writer) =
            tokio::io::duplex(params.max_stdin_buf_size.unwrap());
        let (mut calls_reader, mut calls_writer) =
            tokio::io::duplex(params.max_stdout_buf_size.unwrap());
        let calls = (0..5)
            .map(|index| {
                let mut frame = serde_json::to_vec(&serde_json::json!({
                    "type": "host_tool_call", "id": format!("call-{index}"),
                    "payload": "x".repeat(1400),
                }))
                .unwrap();
                frame.push(b'\n');
                frame
            })
            .collect::<Vec<_>>();
        let write_calls = async {
            for frame in &calls {
                calls_writer.write_all(frame).await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let write_result = async { result_writer.write_all(&vec![b'r'; 1793]).await };
        // No reader runs until both directions finish: kube's 1 KiB defaults
        // deadlock here with parallel calls and one ordinary error result.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::try_join!(write_calls, write_result).unwrap();
        })
        .await
        .expect("parallel attach writes drain");
        drop(calls_writer);
        drop(result_writer);
        let mut call_bytes = Vec::new();
        let mut result_bytes = Vec::new();
        calls_reader.read_to_end(&mut call_bytes).await.unwrap();
        result_reader.read_to_end(&mut result_bytes).await.unwrap();
        assert_eq!(call_bytes, calls.concat());
        assert_eq!(result_bytes.len(), 1793);
    }

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
    fn an_exec_status_reports_its_exit_code() {
        let status = |value: serde_json::Value| {
            serde_json::from_value::<k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>(value)
                .expect("status")
        };
        assert_eq!(
            exit_code(Some(&status(serde_json::json!({"status": "Success"})))).ok(),
            Some(0)
        );
        let failed = status(serde_json::json!({
            "status": "Failure", "reason": "NonZeroExitCode",
            "message": "command terminated with non-zero exit code",
            "details": {"causes": [{"reason": "ExitCode", "message": "127"}]}
        }));
        assert_eq!(exit_code(Some(&failed)).ok(), Some(127));
        assert!(exit_code(Some(&status(serde_json::json!({"status": "Failure"})))).is_err());
        assert!(exit_code(None).is_err());
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
}
