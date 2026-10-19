use super::*;
use std::os::unix::process::CommandExt;

/// One bounded child-process outcome with capped captured streams; shared by
/// the SYS checks and the integration-mode INT-K3S readiness probe.
pub(crate) struct BoundedOutput {
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stdout_truncated: u64,
    pub(crate) stderr_truncated: u64,
}

/// Runs one bounded child command with the runner's disposable environment;
/// shared by the SYS checks and the INT-K3S readiness probe. The child is
/// killed at the deadline, and each captured stream is capped at
/// `OUTPUT_CAP_BYTES` so a chatty child can never grow the sweep's memory.
pub(crate) fn run_bounded(
    program: &Path,
    arguments: &[OsString],
    command_scratch: &Path,
    current_dir: &Path,
    deadline: Instant,
) -> io::Result<BoundedOutput> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "check deadline elapsed before command start",
        ));
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(current_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    runner::configure_command(&mut command, command_scratch)
        .map_err(|error| io::Error::other(format!("command environment rejected: {error}")))?;
    command.process_group(0);
    let mut child = spawn_past_busy_text(&mut command, deadline)?;
    let group = rustix::process::Pid::from_child(&child);
    let kill_group = || {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    };
    let (sender, streams) = mpsc::channel();
    for (index, stream) in [
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .enumerate()
    {
        let mut stream = stream.ok_or_else(|| io::Error::other("piped stream unavailable"))?;
        let sender = sender.clone();
        thread::spawn(move || {
            let _ = sender.send((index, drain_bounded(&mut stream, OUTPUT_CAP_BYTES)));
        });
    }
    drop(sender);
    let mut exit_code = None;
    let mut timed_out = false;
    loop {
        match child.try_wait()? {
            Some(status) => {
                exit_code = status.code();
                break;
            }
            None if Instant::now() >= deadline => {
                timed_out = true;
                kill_group();
                let reaped = Instant::now() + KILL_GRACE;
                while child.try_wait()?.is_none() && Instant::now() < reaped {
                    thread::sleep(Duration::from_millis(20));
                }
                break;
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
    // A descendant can hold the pipes after the child exits. Its group is
    // never signalled once the leader is reaped (the id may belong to another
    // group by then): the streams are awaited until the deadline, then
    // abandoned as a timeout.
    let mut captured: [Option<(Vec<u8>, u64)>; 2] = [None, None];
    let limit = if timed_out {
        Instant::now() + KILL_GRACE
    } else {
        deadline
    };
    while captured.iter().any(Option::is_none) {
        match streams.recv_timeout(limit.saturating_duration_since(Instant::now())) {
            Ok((index, drained)) => captured[index] = Some(drained?),
            Err(_) => {
                timed_out = true;
                break;
            }
        }
    }
    let [stdout, stderr] = captured;
    let (stdout, stdout_truncated) = stdout.unwrap_or_default();
    let (stderr, stderr_truncated) = stderr.unwrap_or_default();
    Ok(BoundedOutput {
        exit_code,
        timed_out,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

/// Spawns, retrying `ETXTBSY` until the deadline. Exec refuses an executable
/// some process still holds open for writing, and that holder can be any
/// fork that inherited the writer's descriptor for the instant before its
/// own exec — a script a sibling check just wrote, or a binary being
/// replaced during activation. The window closes in microseconds; any
/// other spawn error is final.
fn spawn_past_busy_text(
    command: &mut Command,
    deadline: Instant,
) -> io::Result<std::process::Child> {
    loop {
        match command.spawn() {
            Err(error)
                if error.kind() == io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            outcome => return outcome,
        }
    }
}

/// How long a killed process group gets to release its pipes and be reaped.
const KILL_GRACE: Duration = Duration::from_secs(2);

fn drain_bounded(reader: &mut dyn Read, cap: usize) -> io::Result<(Vec<u8>, u64)> {
    let mut buffer = Vec::new();
    let mut truncated = 0_u64;
    let mut chunk = [0_u8; 8_192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok((buffer, truncated)),
            Ok(read) => {
                let take = read.min(cap.saturating_sub(buffer.len()));
                buffer.extend_from_slice(&chunk[..take]);
                truncated += (read - take) as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

pub(in crate::syscheck) fn command_problem(outcome: &BoundedOutput) -> Option<String> {
    if outcome.timed_out {
        Some("command-timeout".to_owned())
    } else if outcome.stdout_truncated != 0 || outcome.stderr_truncated != 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descendant_holding_the_pipes_cannot_outlive_the_deadline() {
        let sleep = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("sleep"))
            .find(|candidate| candidate.is_file())
            .expect("sleep is on PATH");
        let root = tempfile::tempdir().expect("tempdir");
        let script = root.path().join("detach");
        fs::write(
            &script,
            format!("#!/bin/sh\n'{}' 5 &\necho started\n", sleep.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let outcome = run_bounded(
            &script,
            &[],
            root.path(),
            root.path(),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("the bounded child runs");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "returned after {:?}",
            started.elapsed()
        );
        assert!(
            outcome.timed_out,
            "a held pipe past the deadline is a timeout"
        );
        assert_eq!(outcome.exit_code, Some(0));
    }

    #[test]
    fn a_child_past_its_deadline_dies_with_its_whole_group() {
        let sleep = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("sleep"))
            .find(|candidate| candidate.is_file())
            .expect("sleep is on PATH");
        let root = tempfile::tempdir().expect("tempdir");
        let pid_file = root.path().join("descendant.pid");
        let script = root.path().join("hang");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n'{}' 60 &\necho $! > '{}'\nwait\n",
                sleep.display(),
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let outcome = run_bounded(
            &script,
            &[],
            root.path(),
            root.path(),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("the bounded child runs");
        assert!(outcome.timed_out);
        let descendant = fs::read_to_string(&pid_file).expect("descendant pid");
        let proc_dir = format!("/proc/{}", descendant.trim());
        let gone = Instant::now() + Duration::from_secs(5);
        while Path::new(&proc_dir).exists()
            && fs::read_to_string(format!("{proc_dir}/stat"))
                .is_ok_and(|stat| !stat.contains(") Z "))
            && Instant::now() < gone
        {
            thread::sleep(Duration::from_millis(50));
        }
        let alive =
            fs::read_to_string(format!("{proc_dir}/stat")).is_ok_and(|stat| !stat.contains(") Z "));
        assert!(
            !alive,
            "the descendant {descendant} outlived the group kill"
        );
    }

    /// Ordinary bounded children keep the disposable runtime directory: the
    /// scratch `XDG_RUNTIME_DIR` is reserved for other children, so a probe
    /// can never discover live user session state through a child.
    #[test]
    fn ordinary_bounded_children_keep_the_disposable_runtime_directory() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("runtime-dir");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'RuntimeDir=%s\\n' \"$XDG_RUNTIME_DIR\"\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let outcome = run_bounded(
            &script,
            &[],
            root.path(),
            root.path(),
            Instant::now() + Duration::from_secs(20),
        )
        .expect("the bounded child runs");
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        let reported = stdout
            .lines()
            .find_map(|line| line.strip_prefix("RuntimeDir="))
            .expect("the child exported its runtime directory");
        assert_eq!(
            reported,
            root.path().to_str().expect("utf8 scratch"),
            "non-manager children keep the disposable runtime directory"
        );
    }
}
