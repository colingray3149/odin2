use super::*;

/// One bounded child-process outcome with capped captured streams; shared by
/// the SYS checks and the integration-mode INT-K3S readiness probe.
pub(crate) struct BoundedOutput {
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
}

/// Runs one bounded child command with the runner's disposable environment;
/// shared by the SYS checks and the INT-K3S readiness probe. The child's
/// group is killed at the deadline, and each captured stream is capped at
/// `OUTPUT_CAP_BYTES` so a chatty child can never grow the sweep's memory.
pub(crate) fn run_bounded(
    program: &Path,
    arguments: &[OsString],
    command_scratch: &Path,
    current_dir: &Path,
    deadline: Instant,
) -> io::Result<BoundedOutput> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "check deadline elapsed before command start",
        ));
    }
    let mut command = Command::new(program);
    command.args(arguments).current_dir(current_dir);
    runner::configure_command(&mut command, command_scratch)
        .map_err(|error| io::Error::other(format!("command environment rejected: {error}")))?;
    let outcome = odin_process::run_bounded(
        &mut command,
        None,
        odin_process::ChildBounds {
            timeout,
            max_stdout_bytes: OUTPUT_CAP_BYTES,
            max_stderr_bytes: OUTPUT_CAP_BYTES,
        },
    )?;
    Ok(BoundedOutput {
        exit_code: outcome.status.and_then(|status| status.code()),
        timed_out: outcome.status.is_none(),
        stdout_truncated: outcome.stdout.truncated(),
        stderr_truncated: outcome.stderr.truncated(),
        stdout: outcome.stdout.into_bytes(),
        stderr: outcome.stderr.into_bytes(),
    })
}

pub(in crate::syscheck) fn command_problem(outcome: &BoundedOutput) -> Option<String> {
    if outcome.timed_out {
        Some("command-timeout".to_owned())
    } else if outcome.stdout_truncated || outcome.stderr_truncated {
        Some("command-output-truncated".to_owned())
    } else if outcome.exit_code != Some(0) {
        Some(format!(
            "command-exit-{}",
            outcome
                .exit_code
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        ))
    } else {
        None
    }
}

pub(crate) fn trimmed_stdout(outcome: &BoundedOutput) -> String {
    String::from_utf8_lossy(&outcome.stdout).trim().to_owned()
}
