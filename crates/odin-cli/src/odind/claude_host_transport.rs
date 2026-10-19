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
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

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
    pub(crate) fn from_config(
        config: &odin_huginn::OdindConfig,
        manifest: &odin_huginn::RuntimeManifest,
    ) -> Result<Self, String> {
        let executable = manifest
            .executable("ssh")
            .map_err(|error| format!("runtime manifest ssh: {error}"))?
            .path
            .clone();
        let authority = crate::composition::open_stop_authority(
            manifest,
            &config.worker_bus,
            &config.paths.state_root.join("claude-host-authority"),
            "Claude host",
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
                timeout_stop: Duration::from_secs(5),
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
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let executable = self
            .executable
            .to_str()
            .ok_or_else(|| "registered SSH executable is not UTF-8".to_owned())?;
        let request = serde_json::to_string(request)
            .map_err(|error| format!("host request serialization failed: {error}"))?;
        let argv = FrozenArgv::new(
            ssh_arguments(executable, host, remote_command(script, &request)),
            16,
            OUTPUT_LIMIT,
        )
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
        self.worker
            .authority
            .close_worker_stdin(&worker_id)
            .map_err(|error| format!("registered SSH stdin close on {host} failed: {error}"))?;

        // Separate drains prevent either pipe from blocking the remote command.
        // Excess stdout fails the command. Stderr is drained fully and only a
        // short tail is kept for the failure report.
        let (out_tx, out_rx) = mpsc::sync_channel(1);
        let stdout = thread::Builder::new()
            .name("claude-host-stdout".to_owned())
            .spawn(move || {
                let _ = out_tx.send(read_bounded(launched.stdout));
            })
            .map_err(|error| format!("registered SSH stdout drain could not start: {error}"))?;
        let (err_tx, err_rx) = mpsc::sync_channel(1);
        let stderr = thread::Builder::new()
            .name("claude-host-stderr".to_owned())
            .spawn(move || {
                let _ = err_tx.send(read_stderr_tail(launched.stderr));
            })
            .map_err(|error| format!("registered SSH stderr drain could not start: {error}"))?;
        let status = loop {
            if Instant::now() >= deadline {
                break Err(format!(
                    "registered SSH command on {host} exceeded its deadline"
                ));
            }
            match self.worker.authority.try_wait_worker(&worker_id) {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(10)),
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
        let output = output?;
        let stderr_tail = errors?;
        if !status.success() {
            return Err(command_failure(host, &status, &stderr_tail));
        }
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

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let take = OUTPUT_LIMIT.saturating_sub(kept.len()).min(read);
                kept.extend_from_slice(&chunk[..take]);
                overflow |= take < read;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("registered SSH output read failed: {error}")),
        }
    }
    if overflow {
        return Err("registered SSH output exceeded 1 MiB".to_owned());
    }
    Ok(kept)
}

fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn remote_command(script: &str, request: &str) -> String {
    ["python3", "-c", script, request]
        .map(shell_quote)
        .join(" ")
}

/// `-F none`: the worker's user namespace maps the owner of `~/.ssh/config`
/// to nobody, and ssh refuses that file. Strict host-key checking stays on.
fn ssh_arguments(executable: &str, host: &str, remote: String) -> Vec<String> {
    vec![
        executable.to_owned(),
        "-F".to_owned(),
        "none".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=10".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "--".to_owned(),
        host.to_owned(),
        remote,
    ]
}

const STDERR_TAIL: usize = 300;

/// Drain stderr completely. Keep only the last [`STDERR_TAIL`] bytes.
fn read_stderr_tail(mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if kept.capacity() == 0 {
                    kept.reserve_exact(STDERR_TAIL);
                }
                if read >= STDERR_TAIL {
                    kept.clear();
                    kept.extend_from_slice(&chunk[read - STDERR_TAIL..read]);
                } else {
                    let discard = (kept.len() + read).saturating_sub(STDERR_TAIL);
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

    use super::{
        command_failure, read_bounded, read_stderr_tail, remote_command, shell_quote, OUTPUT_LIMIT,
        STDERR_TAIL,
    };

    #[test]
    fn shell_quotes_empty_and_hostile_words() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            shell_quote("$(touch /tmp/injected); `id`\n\"$HOME\"\\"),
            "'$(touch /tmp/injected); `id`\n\"$HOME\"\\'"
        );
    }

    #[test]
    fn remote_command_quotes_every_word() {
        assert_eq!(
            remote_command("print('hello');\n# $HOME", "{\"x\":\"'; $(id)\"}"),
            "'python3' '-c' 'print('\\''hello'\\'');\n# $HOME' '{\"x\":\"'\\''; $(id)\"}'"
        );
    }

    #[test]
    fn bounded_reader_drains_excess_and_accepts_the_exact_limit() {
        let bytes = vec![b'x'; OUTPUT_LIMIT + 1];
        let mut reader = std::io::Cursor::new(&bytes);
        assert!(read_bounded(&mut reader).is_err());
        assert_eq!(reader.position(), bytes.len() as u64);
        assert_eq!(
            read_bounded(&bytes[..OUTPUT_LIMIT]).unwrap(),
            bytes[..OUTPUT_LIMIT]
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

    #[test]
    fn stderr_tail_keeps_the_last_bytes_and_drains_the_rest() {
        let bytes = (0..=255).cycle().take(2 * 8192 + 50).collect::<Vec<_>>();
        let mut reader = std::io::Cursor::new(&bytes);
        let tail = read_stderr_tail(&mut reader).unwrap();
        assert_eq!(reader.position(), bytes.len() as u64);
        assert_eq!(tail, &bytes[bytes.len() - STDERR_TAIL..]);
    }
}
