use odin_omp::process::OmpWorkerLaunch;
use odin_process::{CommandSpec, EnvironmentBuilder, FrozenArgv, CORRELATION_ENV};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 1024 * 1024;
/// How long a stopped SSH worker gets to exit before it is killed.
const WORKER_STOP_GRACE: Duration = Duration::from_secs(5);
/// How often the blocking wait for the worker's exit looks again.
const WAIT_POLL: Duration = Duration::from_millis(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one command's whole stdin may take to be accepted.
const STDIN_TIMEOUT: Duration = Duration::from_secs(90);

/// Executes a declared remote host's helper through its registered SSH binding.
/// Failures name the host, the exit status, and a short stderr tail. The
/// command arguments and the environment are not included.
pub(crate) struct ClaudeHostTransport {
    worker: OmpWorkerLaunch,
    executable: PathBuf,
    current_dir: PathBuf,
    attempt: AtomicU32,
}

impl ClaudeHostTransport {
    /// `authority` names this user's private stop-authority directory under
    /// the state root and `label` its log name: each user owns its own.
    pub(crate) fn from_config(
        config: &odin_huginn::OdindConfig,
        manifest: &odin_huginn::RuntimeManifest,
        authority: &str,
        label: &str,
    ) -> Result<Self, String> {
        let executable = manifest
            .executable("ssh")
            .map_err(|error| format!("runtime manifest ssh: {error}"))?
            .path
            .clone();
        let authority = crate::composition::open_stop_authority(
            manifest,
            &config.worker_bus,
            &config.paths.state_root.join(authority),
            label,
        )?;
        let seed = odin_process::mint_worker_id().map_err(|error| error.to_string())?;
        let correlation =
            odin_types::CorrelationId::new(seed.as_str()).map_err(|error| error.to_string())?;
        let worker = OmpWorkerLaunch::new(
            authority,
            correlation,
            "odind",
            "claude-host",
            1,
            crate::composition::registered_runtime_binding(manifest, "ssh", &executable)?,
            odin_process::ScopeLimits {
                lifetime: odin_process::ScopeLifetime::Bounded(COMMAND_TIMEOUT),
                timeout_stop: WORKER_STOP_GRACE,
                ..odin_process::ScopeLimits::default()
            },
        )
        .map_err(|error| format!("Claude host worker launch binding rejected: {error}"))?;
        Ok(Self::new(
            worker,
            executable,
            config.paths.state_root.clone(),
        ))
    }

    pub fn new(worker: OmpWorkerLaunch, executable: PathBuf, current_dir: PathBuf) -> Self {
        Self {
            worker,
            executable,
            current_dir,
            attempt: AtomicU32::new(1),
        }
    }

    pub fn run(
        &self,
        host: &str,
        script: &str,
        request: &serde_json::Value,
    ) -> Result<Vec<u8>, String> {
        let request = serde_json::to_string(request)
            .map_err(|error| format!("host request serialization failed: {error}"))?;
        // The request rides stdin, never argv: `ps` on either host must not
        // show the payload or its declared MCP environment values.
        self.run_remote(
            host,
            remote_command(script),
            Some(request.as_bytes()),
            OUTPUT_LIMIT,
        )
    }

    /// Runs one already-quoted remote command line on `host`, feeding it
    /// `input` on stdin and keeping at most `output_limit` bytes of its stdout.
    pub fn run_remote(
        &self,
        host: &str,
        remote: String,
        input: Option<&[u8]>,
        output_limit: usize,
    ) -> Result<Vec<u8>, String> {
        self.run_remote_io(
            host,
            remote,
            input.map(|bytes| {
                Box::new(std::io::Cursor::new(bytes.to_vec())) as Box<dyn Read + Send>
            }),
            None,
            output_limit,
        )
    }

    /// Streams binary file transfers through registered SSH without retaining
    /// the object in either the stdin or stdout drain.
    pub fn run_remote_file(
        &self,
        host: &str,
        remote: String,
        input: Option<std::fs::File>,
        output: Option<std::fs::File>,
    ) -> Result<Vec<u8>, String> {
        self.run_remote_io(
            host,
            remote,
            input.map(|file| Box::new(file) as Box<dyn Read + Send>),
            output,
            64 * 1024,
        )
    }

    fn run_remote_io(
        &self,
        host: &str,
        remote: String,
        input: Option<Box<dyn Read + Send>>,
        output_file: Option<std::fs::File>,
        output_limit: usize,
    ) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let executable = self
            .executable
            .to_str()
            .ok_or_else(|| "registered SSH executable is not UTF-8".to_owned())?;
        let argv = FrozenArgv::new(ssh_arguments(executable, host, remote), 16, OUTPUT_LIMIT)
            .map_err(|error| format!("registered SSH arguments rejected: {error}"))?;
        let environment = EnvironmentBuilder::new([
            CORRELATION_ENV,
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "USER",
            "LOGNAME",
            "SSH_AUTH_SOCK",
        ])
        .map_err(|error| format!("registered SSH environment rejected: {error}"))?
        .capture_current()
        .map_err(|error| format!("registered SSH environment capture failed: {error}"))?
        .set(CORRELATION_ENV, self.worker.correlation_id.as_str())
        .map_err(|error| format!("registered SSH correlation rejected: {error}"))?
        .build();
        let spec = CommandSpec {
            argv,
            environment,
            current_dir: self.current_dir.clone(),
        };
        let worker_id = odin_process::mint_worker_id()
            .map_err(|error| format!("registered SSH worker identity failed: {error}"))?;
        let naming = odin_process::WorkerNaming::new(
            "odind",
            "claude-host",
            self.attempt.fetch_add(1, Ordering::Relaxed),
            worker_id,
        )
        .map_err(|error| format!("registered SSH naming failed: {error}"))?;
        let mut guard = HostStopGuard {
            authority: Arc::clone(&self.worker.authority),
            worker_id: None,
        };
        let launched = self
            .worker
            .authority
            .launch_registered_service(
                naming,
                &self.worker.correlation_id,
                &spec,
                self.worker.limits,
                &self.worker.binding,
            )
            .map_err(|error| format!("registered SSH launch on {host} failed: {error}"))?;
        let worker_id = launched.identity.worker_id.clone();
        guard.worker_id = Some(worker_id.clone());

        // Separate drains prevent either pipe from blocking the remote command.
        // Excess stdout fails the command. Stderr is drained fully and only a
        // short tail is kept for the failure report.
        let (out_tx, out_rx) = mpsc::sync_channel(1);
        let stdout = thread::Builder::new()
            .name("claude-host-stdout".to_owned())
            .spawn(move || {
                let result = match output_file {
                    Some(mut file) => std::io::copy(&mut { launched.stdout }, &mut file)
                        .and_then(|_| file.sync_all())
                        .map(|()| Vec::new())
                        .map_err(|error| format!("streaming SSH stdout failed: {error}")),
                    None => read_bounded(launched.stdout, output_limit),
                };
                let _ = out_tx.send(result);
            })
            .map_err(|error| format!("registered SSH stdout drain could not start: {error}"))?;
        let (err_tx, err_rx) = mpsc::sync_channel(1);
        let stderr = thread::Builder::new()
            .name("claude-host-stderr".to_owned())
            .spawn(move || {
                let _ = err_tx.send(read_stderr_tail(launched.stderr, STDERR_TAIL));
            })
            .map_err(|error| format!("registered SSH stderr drain could not start: {error}"))?;
        let (input_tx, input_rx) = mpsc::sync_channel(1);
        let authority = Arc::clone(&self.worker.authority);
        let input_worker = worker_id.clone();
        let stdin = thread::Builder::new()
            .name("host-file-stdin".to_owned())
            .spawn(move || {
                let result = (|| -> Result<(), String> {
                    if let Some(mut input) = input {
                        let mut buffer = [0; 64 * 1024];
                        loop {
                            let count =
                                input.read(&mut buffer).map_err(|error| error.to_string())?;
                            if count == 0 {
                                break;
                            }
                            authority
                                .write_worker_stdin_timeout(
                                    &input_worker,
                                    &buffer[..count],
                                    STDIN_TIMEOUT,
                                )
                                .map_err(|error| error.to_string())?;
                        }
                    }
                    authority
                        .close_worker_stdin(&input_worker)
                        .map_err(|error| error.to_string())
                })();
                let _ = input_tx.send(result);
            })
            .map_err(|error| format!("registered SSH stdin drain could not start: {error}"))?;
        let status = loop {
            if Instant::now() >= deadline {
                break Err(format!(
                    "registered SSH command on {host} exceeded its deadline"
                ));
            }
            match self.worker.authority.try_wait_worker(&worker_id) {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(WAIT_POLL),
                Err(error) => break Err(format!("registered SSH wait on {host} failed: {error}")),
            }
        };
        let outcome = self
            .worker
            .authority
            .stop_worker(&worker_id)
            .map_err(|error| format!("registered SSH stop on {host} failed: {error}"))?;
        if outcome.verdict != odin_domain::StopVerdict::Stopped {
            return Err(format!(
                "registered SSH worker stop on {host} was not proved: {:?}",
                outcome.verdict
            ));
        }
        guard.worker_id = None;
        let status = status?;
        let output = out_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                format!("registered SSH stdout drain on {host} failed or exceeded its deadline: {error}")
            })?;
        let errors = err_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                format!("registered SSH stderr drain on {host} failed or exceeded its deadline: {error}")
            })?;
        stdout.join().map_err(|panic| {
            format!(
                "registered SSH stdout drain on {host} panicked: {}",
                panic_cause(panic.as_ref())
            )
        })?;
        stderr.join().map_err(|panic| {
            format!(
                "registered SSH stderr drain on {host} panicked: {}",
                panic_cause(panic.as_ref())
            )
        })?;
        let input_result = input_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                format!("registered SSH stdin to {host} exceeded its deadline: {error}")
            });
        stdin
            .join()
            .map_err(|_| "registered SSH stdin panicked".to_owned())?;
        let output = output?;
        let stderr_tail = errors?;
        if !status.success() {
            return Err(command_failure(host, &status, &stderr_tail));
        }
        input_result??;
        Ok(output)
    }
}

struct HostStopGuard {
    authority: Arc<odin_kernel::StopAuthority>,
    worker_id: Option<odin_types::WorkerId>,
}

impl Drop for HostStopGuard {
    fn drop(&mut self) {
        if let Some(worker_id) = self.worker_id.take() {
            if let Err(error) = self.authority.stop_worker(&worker_id) {
                tracing::error!("registered SSH worker stop on drop failed: {error}");
            }
        }
    }
}

fn panic_cause(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else {
        "non-string panic payload"
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let take = limit.saturating_sub(kept.len()).min(read);
                kept.extend_from_slice(&chunk[..take]);
                overflow |= take < read;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("registered SSH output read failed: {error}")),
        }
    }
    if overflow {
        return Err(format!("registered SSH output exceeded {limit} bytes"));
    }
    Ok(kept)
}

pub(crate) fn remote_command(script: &str) -> String {
    ["python3", "-c", script]
        .map(odin_process::shell_quote)
        .join(" ")
}

/// `-F none`: the worker's user namespace maps the owner of `~/.ssh/config`
/// to nobody, and ssh refuses that file. Strict host-key checking stays on.
fn ssh_arguments(executable: &str, host: &str, remote: String) -> Vec<String> {
    let mut argv = vec![executable.to_owned()];
    argv.extend(odin_omp::live::harness::ssh_argv(
        &["-o", "StrictHostKeyChecking=yes"],
        host,
        &[remote.as_str()],
    ));
    argv
}

const STDERR_TAIL: usize = 300;

/// Drain stderr completely. Keep only the last `limit` bytes.
pub(super) fn read_stderr_tail(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if kept.capacity() == 0 {
                    kept.reserve_exact(limit);
                }
                if read >= limit {
                    kept.clear();
                    kept.extend_from_slice(&chunk[read - limit..read]);
                } else {
                    let discard = (kept.len() + read).saturating_sub(limit);
                    kept.drain(..discard);
                    kept.extend_from_slice(&chunk[..read]);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("registered SSH stderr read failed: {error}")),
        }
    }
    Ok(kept)
}

fn command_failure(host: &str, status: &std::process::ExitStatus, stderr: &[u8]) -> String {
    use std::os::unix::process::ExitStatusExt;
    let status_text = match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit {code}"),
        (None, Some(signal)) => format!("signal {signal}"),
        (None, None) => "exit none".to_owned(),
    };
    let tail = String::from_utf8_lossy(stderr);
    let tail = tail.trim();
    if tail.is_empty() {
        format!("registered SSH command failed on host {host}: {status_text}; stderr empty")
    } else {
        format!("registered SSH command failed on host {host}: {status_text}; stderr: {tail}")
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::{command_failure, remote_command, STDERR_TAIL};

    #[test]
    fn remote_command_quotes_script_and_carries_no_request() {
        assert_eq!(
            remote_command("print('hello');\n# $HOME"),
            "'python3' '-c' 'print('\\''hello'\\'');\n# $HOME'"
        );
    }

    #[test]
    fn command_failure_names_host_status_and_a_bounded_stderr_tail() {
        let status = ExitStatus::from_raw(255 << 8);
        let stderr = b"prefix-secret-material-".repeat(40);
        let message = command_failure("pc", &status, &stderr[stderr.len() - STDERR_TAIL..]);
        assert!(message.contains("host pc"), "{message}");
        assert!(message.contains("exit 255"), "{message}");
        assert!(message.contains("stderr:"), "{message}");
        assert!(message.len() < 500, "{message}");
        let killed = command_failure("pc", &ExitStatus::from_raw(9), b"");
        assert!(killed.contains("signal 9"), "{killed}");
        assert!(killed.contains("stderr empty"), "{killed}");
    }
}
