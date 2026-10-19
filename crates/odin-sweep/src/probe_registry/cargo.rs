//! Shared cargo-test execution and libtest output validation.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Wall-clock bound on one cargo test run, cold workspace test build included.
const CARGO_RUN_LIMIT: Duration = Duration::from_secs(60 * 60);

/// Retains stdout on failure to distinguish unavailable prerequisites from test defects;
/// `failure` records why the run failed.
pub(super) struct CargoRun {
    pub(super) ok: bool,
    pub(super) stdout: String,
    pub(super) failure: Option<String>,
}

impl CargoRun {
    /// The stdout when the run succeeded, else the failure reason.
    pub(super) fn ok_stdout(&self) -> Result<&str, &str> {
        if self.ok {
            Ok(&self.stdout)
        } else {
            Err(self
                .failure
                .as_deref()
                .unwrap_or("cargo test did not succeed"))
        }
    }
}

/// Isolates HOME/XDG state while retaining Cargo caches and applying the supplied environment.
/// Streams stderr and forwards stdout, retaining stdout on failure for unavailability diagnostics.
/// Limits build parallelism to bound memory use.
pub(super) fn run_cargo_tests(
    odin_root: &Path,
    scratch: &Path,
    arguments: &[&str],
    environment: &[(String, OsString)],
) -> CargoRun {
    let split = arguments
        .iter()
        .position(|argument| *argument == "--")
        .unwrap_or(arguments.len());
    let mut bounded: Vec<&str> = Vec::with_capacity(arguments.len() + 4);
    bounded.extend_from_slice(&arguments[..split]);
    bounded.extend_from_slice(&["-j", "3"]);
    bounded.extend_from_slice(&arguments[split..]);
    let mut command = crate::runner::cargo_command(odin_root, scratch, &bounded);
    let started_child = crate::runner::configure_command(&mut command, scratch)
        .map(|()| {
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .env_remove("RUST_TEST_NOCAPTURE")
                .process_group(0);
            for (key, value) in environment {
                command.env(key, value);
            }
        })
        .and_then(|()| command.spawn().map_err(|error| error.to_string()));
    let mut child = match started_child {
        Ok(child) => child,
        Err(error) => {
            return CargoRun {
                ok: false,
                stdout: String::new(),
                failure: Some(format!("could not start the cargo test command: {error}")),
            };
        }
    };
    let run = wait_bounded(&mut child, arguments, Instant::now() + CARGO_RUN_LIMIT);
    // A failed diagnostic write must fail the run.
    if let Err(error) = io::stdout().write_all(run.stdout.as_bytes()) {
        return CargoRun {
            ok: false,
            stdout: run.stdout,
            failure: Some(format!("could not forward cargo output: {error}")),
        };
    }
    run
}

/// Reads cargo's stdout and waits for it until `deadline`; past it the whole
/// process group (cargo, rustc, the libtest binaries) is killed.
fn wait_bounded(
    child: &mut std::process::Child,
    arguments: &[&str],
    deadline: Instant,
) -> CargoRun {
    let group = rustix::process::Pid::from_child(child);
    let mut pipe = child.stdout.take().expect("stdout was piped");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut stdout = String::new();
        let read = pipe.read_to_string(&mut stdout).map(|_| ());
        let _ = sender.send((stdout, read));
    });
    let (stdout, read) =
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(drained) => drained,
            Err(_) => {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                let _ = child.wait();
                let stdout = receiver
                    .recv_timeout(Duration::from_secs(5))
                    .map(|(stdout, _)| stdout)
                    .unwrap_or_default();
                return CargoRun {
                    ok: false,
                    stdout,
                    failure: Some(format!(
                    "cargo {arguments:?} did not finish within {}s; its process group was killed",
                    CARGO_RUN_LIMIT.as_secs()
                )),
                };
            }
        };
    if let Err(error) = read {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        reap_within(child, Duration::from_secs(5));
        return CargoRun {
            ok: false,
            stdout,
            failure: Some(format!("could not read cargo output: {error}")),
        };
    }
    match child.wait() {
        Ok(status) if status.success() => CargoRun {
            ok: true,
            stdout,
            failure: None,
        },
        Ok(status) => CargoRun {
            ok: false,
            stdout,
            failure: Some(format!("cargo {arguments:?} exited with {status}")),
        },
        Err(error) => {
            let _ = child.kill();
            CargoRun {
                ok: false,
                stdout,
                failure: Some(format!("could not wait for cargo: {error}")),
            }
        }
    }
}

/// Reaps a killed child, giving up after `grace` (a D-state child cannot hang
/// the sweep).
fn reap_within(child: &mut std::process::Child, grace: Duration) {
    let until = Instant::now() + grace;
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < until {
        thread::sleep(Duration::from_millis(50));
    }
}

/// True only when libtest printed the exact passing line for `selector` and a
/// one-pass summary: `cargo test <filter>` matches nothing with exit status
/// zero, so the summary is load-bearing.
pub(super) fn single_test_passed(stdout: &str, selector: &str) -> bool {
    let test_line = format!("test {selector} ... ok");
    stdout.lines().any(|line| line.trim() == test_line)
        && stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed;") && line.contains("0 failed"))
}

/// True only when every required selection printed its exact passing line and
/// every libtest summary reported ok with zero failures and a total covering
/// every required selection. `cargo test` matching nothing exits zero, so the
/// required lines and counts are load-bearing.
pub(super) fn suite_output_confirms_full_pass(stdout: &str, required: &[&str]) -> bool {
    let confirmed = |selector: &str| {
        let test_line = format!("test {selector} ... ok");
        stdout.lines().any(|line| line.trim() == test_line)
    };
    if !required.iter().all(|selector| confirmed(selector)) {
        return false;
    }
    let mut summaries = 0usize;
    let mut total_passed = 0usize;
    for line in stdout.lines() {
        let Some(counts) = line.trim().strip_prefix("test result: ") else {
            continue;
        };
        let Some(counts) = counts.strip_prefix("ok. ") else {
            return false;
        };
        let Some((passed_token, after_passed)) = counts.split_once(" passed;") else {
            return false;
        };
        let Ok(passed) = passed_token.parse::<usize>() else {
            return false;
        };
        let failed_token: String = after_passed
            .trim_start()
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .collect();
        let Ok(failed) = failed_token.parse::<usize>() else {
            return false;
        };
        if failed != 0 {
            return false;
        }
        summaries += 1;
        total_passed += passed;
    }
    summaries > 0 && total_passed > 0 && total_passed >= required.len()
}
