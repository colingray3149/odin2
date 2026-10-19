use odin_domain::huginn::LiveError;
use odin_process::{CommandSpec, EnvironmentBuilder, FrozenArgv, CORRELATION_ENV};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration as StdDuration;

use super::open_abandoned;
use crate::live::zellij::{
    invalid_terminal, io_error, limit_error, unavailable, MAX_TERMINAL_BYTES,
};
use crate::process::OmpWorkerLaunch;

/// Listings grow with pane count and need a larger cap than individual screen captures.
const MAX_ACTION_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// [`run_zellij_blocking`] on the blocking pool for a read outside any
/// workflow. A caller that leaves while the run is still queued never
/// launches it; a started run carries its worker to its own stop attempt,
/// so cancelling this future abandons only the reply.
pub(super) async fn run_zellij(
    executable: &Path,
    worker: &OmpWorkerLaunch,
    current_dir: &Path,
    command_timeout: StdDuration,
    args: Vec<String>,
) -> Result<Vec<u8>, LiveError> {
    let executable = executable.to_path_buf();
    let worker = worker.clone();
    let current_dir = current_dir.to_path_buf();
    let (reply, receive) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        if !reply.is_closed() {
            let _ = reply.send(run_zellij_blocking(
                &executable,
                &worker,
                &current_dir,
                command_timeout,
                args,
                &|| false,
            ));
        }
    });
    receive.await.map_err(|_| unavailable())?
}

/// One bounded registered-service zellij run on the calling blocking
/// thread. StopAuthority owns launch, stdin, wait, and stop; no Command
/// spawn, no PGID, and no kill-on-drop fallback exists on this path.
/// `args` is the argv after the executable. Both pipes are read
/// nonblocking inside the exit poll, so a full pipe never stalls the child,
/// and they close with this frame on every path: no reader outlives a run.
/// `cut` ends the wait early but still stops the worker.
pub(super) fn run_zellij_blocking(
    executable: &Path,
    worker: &OmpWorkerLaunch,
    current_dir: &Path,
    command_timeout: StdDuration,
    args: Vec<String>,
    cut: &dyn Fn() -> bool,
) -> Result<Vec<u8>, LiveError> {
    let mut full: Vec<String> = Vec::with_capacity(args.len().saturating_add(1));
    full.push(executable.to_string_lossy().into_owned());
    full.extend(args);
    let naming = worker
        .next_naming()
        .map_err(|error| invalid_terminal(error.to_string()))?;
    let argv =
        FrozenArgv::new(full, 128, 1024 * 1024).map_err(|e| invalid_terminal(e.to_string()))?;
    let allowed = [
        CORRELATION_ENV,
        "HOME",
        "PATH",
        "TERM",
        "LANG",
        "LC_ALL",
        "SHELL",
        "USER",
        "LOGNAME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    ];
    let environment = EnvironmentBuilder::new(allowed)
        .map_err(|e| invalid_terminal(e.to_string()))?
        .capture_current()
        .map_err(|e| invalid_terminal(e.to_string()))?
        .set(CORRELATION_ENV, worker.correlation_id.as_str())
        .map_err(|e| invalid_terminal(e.to_string()))?
        .build();
    let spec = CommandSpec {
        argv,
        environment,
        current_dir: current_dir.to_path_buf(),
    };
    let authority = &worker.authority;
    // Every early return or panic attempts a bounded stop until termination is confirmed.
    let mut guard = ActionStopGuard {
        stop_worker: |worker_id: &odin_types::WorkerId| {
            authority
                .stop_worker_bounded(worker_id, std::time::Instant::now() + ACTION_STOP_BUDGET)
                .map(|outcome| outcome.verdict)
                .map_err(|error| invalid_terminal(error.to_string()))
        },
        worker_id: None,
    };
    let launched = authority
        .launch_registered_service(
            naming,
            &worker.correlation_id,
            &spec,
            worker.limits,
            &worker.binding,
        )
        .map_err(|error| invalid_terminal(error.to_string()))?;
    let worker_id = launched.identity.worker_id.clone();
    guard.worker_id = Some(worker_id.clone());
    let _ = authority.close_worker_stdin(&worker_id);
    let mut stdout = PipeDrain::open(launched.stdout, MAX_ACTION_OUTPUT_BYTES).map_err(io_error)?;
    let mut stderr = PipeDrain::open(launched.stderr, MAX_TERMINAL_BYTES).map_err(io_error)?;
    let deadline = std::time::Instant::now() + command_timeout;
    let status = loop {
        stdout.read_available();
        stderr.read_available();
        if std::time::Instant::now() >= deadline || cut() {
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        match authority.try_wait_worker(&worker_id) {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
    };
    // An unconfirmed stop is an error, even after observing exit.
    guard.stop()?;
    // Writers have stopped; drain remaining bytes under the original action deadline.
    loop {
        stdout.read_available();
        stderr.read_available();
        if stdout.closed && stderr.closed {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(LiveError::Unavailable {
                code: "zellij_adapter: drain timeout".to_owned(),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let Some(status) = status else {
        if cut() {
            return Err(open_abandoned());
        }
        return Err(LiveError::Unavailable {
            code: format!(
                "zellij_adapter: action timed out after {:?}",
                command_timeout
            ),
        });
    };
    if !status.success() {
        return Err(LiveError::Unavailable {
            code: "zellij_action".to_owned(),
        });
    }
    if stdout.overflow || stderr.overflow {
        return Err(limit_error("zellij action output", MAX_ACTION_OUTPUT_BYTES));
    }
    Ok(stdout.kept)
}

/// Caps explicit stop and guard retries so the blocking pool cannot wait indefinitely.
const ACTION_STOP_BUDGET: StdDuration = StdDuration::from_secs(10);

/// One action pipe, read nonblocking from the run's exit poll. It keeps at
/// most `cap` bytes, records overflow, and closes at EOF or a read error.
struct PipeDrain {
    file: fs::File,
    cap: usize,
    kept: Vec<u8>,
    overflow: bool,
    closed: bool,
}

impl PipeDrain {
    fn open(pipe: impl Into<std::os::fd::OwnedFd>, cap: usize) -> std::io::Result<Self> {
        let file = fs::File::from(pipe.into());
        let errno = |e: rustix::io::Errno| std::io::Error::from_raw_os_error(e.raw_os_error());
        let flags = rustix::fs::fcntl_getfl(&file).map_err(errno)?;
        rustix::fs::fcntl_setfl(&file, flags.union(rustix::fs::OFlags::NONBLOCK)).map_err(errno)?;
        Ok(Self {
            file,
            cap,
            kept: Vec::new(),
            overflow: false,
            closed: false,
        })
    }

    /// Reads what is available now, at most 64 chunks so a writer that
    /// never pauses still lets the poll reach its deadline.
    fn read_available(&mut self) {
        let mut chunk = [0u8; 8192];
        for _ in 0..64 {
            if self.closed {
                return;
            }
            match self.file.read(&mut chunk) {
                Ok(0) => self.closed = true,
                Ok(read) => {
                    let take = self.cap.saturating_sub(self.kept.len()).min(read);
                    self.kept.extend_from_slice(&chunk[..take]);
                    self.overflow |= read > take;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => self.closed = true,
            }
        }
    }
}

/// Only `Stopped` disarms this guard; other outcomes leave a bounded retry on drop.
/// Pending rows remain available to [`odin_kernel::StopAuthority::recover_pending`].
struct ActionStopGuard<F>
where
    F: FnMut(&odin_types::WorkerId) -> Result<odin_domain::StopVerdict, LiveError>,
{
    stop_worker: F,
    worker_id: Option<odin_types::WorkerId>,
}

impl<F> ActionStopGuard<F>
where
    F: FnMut(&odin_types::WorkerId) -> Result<odin_domain::StopVerdict, LiveError>,
{
    fn stop(&mut self) -> Result<(), LiveError> {
        let Some(worker_id) = self.worker_id.as_ref() else {
            return Ok(());
        };
        let verdict = (self.stop_worker)(worker_id)?;
        if verdict != odin_domain::StopVerdict::Stopped {
            return Err(invalid_terminal(format!(
                "zellij action {worker_id} stop was not proved: {verdict:?}"
            )));
        }
        self.worker_id = None;
        Ok(())
    }
}

impl<F> Drop for ActionStopGuard<F>
where
    F: FnMut(&odin_types::WorkerId) -> Result<odin_domain::StopVerdict, LiveError>,
{
    fn drop(&mut self) {
        if let Some(worker_id) = self.worker_id.take() {
            match (self.stop_worker)(&worker_id) {
                Ok(odin_domain::StopVerdict::Stopped) => {}
                Ok(verdict) => tracing::error!(
                    "odin-omp: zellij action drop-stop worker={worker_id} proof=unproved \
                     verdict={verdict:?}"
                ),
                Err(error) => tracing::error!(
                    "odin-omp: zellij action drop-stop worker={worker_id} proof=unproved \
                     error={error}"
                ),
            }
        }
    }
}

/// The blocking-action lifecycle against the registered-worker fixture:
/// the private manager behind `launch_for_fixture` runs the production
/// launch, wait, and stop paths, so cancellation, deadline, and failure
/// below observe real payload processes, not wiring mocks.
#[cfg(test)]
mod tests {
    use super::run_zellij;
    use crate::process::launch_for_fixture;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// A payload script that records its pid, then runs `body`.
    fn payload(root: &Path, pid_path: &Path, body: &str) -> PathBuf {
        let executable = root.join("zellij-action");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\necho $$ > {}\n{}\n", pid_path.display(), body),
        )
        .expect("payload script");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod payload");
        executable
    }

    /// Waits until the pid file the payload writes appears, then parses it.
    async fn read_pid_file(path: &Path) -> u32 {
        for _ in 0..200 {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(pid) = contents.trim().parse() {
                    return pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("pid file {} never appeared", path.display());
    }

    /// Polls procfs until `pid` is gone: dead and reaped, not a zombie.
    async fn wait_until_dead(pid: u32) -> bool {
        for _ in 0..200 {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// Polls the durable store read-only until no nonterminal worker row
    /// remains for `correlation`; unlike `recover_pending` it never
    /// actuates, so cleanup that never happens is observed as failure.
    async fn wait_until_terminal(
        authority: &odin_kernel::StopAuthority,
        correlation: &str,
    ) -> bool {
        let store = authority.store();
        for _ in 0..200 {
            let nonterminal = {
                let ledger = store.lock().expect("ledger lock");
                odin_ledger::worker::nonterminal_rows(ledger.connection(), Some(correlation))
                    .expect("nonterminal rows")
                    .len()
            };
            if nonterminal == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_cancelled_action_still_stops_its_worker() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let pid_path = root.join("payload.pid");
        let executable = payload(&root, &pid_path, "sleep 30");
        let worker = launch_for_fixture(&executable);
        let authority = worker.authority.clone();
        let correlation = worker.correlation_id.clone();

        // Abandon the run exactly while the payload is running: the select
        // drops the pending `run_zellij` future the moment the pid file
        // proves the launched scope exists. The 3 s command deadline sits
        // well inside the 10 s death budget: the run polls to its deadline
        // on its own blocking thread, then stops the payload.
        let pid = tokio::select! {
            pid = read_pid_file(&pid_path) => pid,
            outcome = run_zellij(
                &executable,
                &worker,
                &root,
                Duration::from_secs(3),
                Vec::new(),
            ) => panic!("the blocking payload ended the run: {outcome:?}"),
        };

        assert!(
            wait_until_dead(pid).await,
            "the abandoned action stops its own payload"
        );
        // Check the durable outcome before recovery can hide a missed stop.
        assert!(
            wait_until_terminal(&authority, correlation.as_str()).await,
            "the action's stop proves itself in the ledger"
        );
        let outcomes = authority
            .recover_pending(Some(&correlation))
            .expect("recovery sweep");
        assert!(
            outcomes.is_empty(),
            "the stop proved itself durably: {outcomes:?}"
        );
    }

    /// A payload past its command deadline is refused typed and stopped by
    /// the action; a deadline is never a silent success or a leaked worker.
    #[tokio::test]
    async fn an_action_past_its_deadline_is_stopped_and_refused() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let pid_path = root.join("payload.pid");
        let executable = payload(&root, &pid_path, "sleep 30");
        let worker = launch_for_fixture(&executable);

        let refused = run_zellij(
            &executable,
            &worker,
            &root,
            Duration::from_millis(200),
            Vec::new(),
        )
        .await
        .expect_err("a payload past the deadline is refused");
        assert!(
            matches!(&refused, odin_domain::huginn::LiveError::Unavailable { .. }),
            "{refused:?}"
        );
        let pid = read_pid_file(&pid_path).await;
        assert!(
            wait_until_dead(pid).await,
            "the timed-out payload is stopped"
        );
    }

    /// A confirmed stop disarms the guard, avoiding a second stop on nonzero exit.
    #[tokio::test]
    async fn a_failing_action_is_refused_and_stopped() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let pid_path = root.join("payload.pid");
        let executable = payload(&root, &pid_path, "printf out; printf err >&2; exit 3");
        let worker = launch_for_fixture(&executable);

        let refused = run_zellij(
            &executable,
            &worker,
            &root,
            Duration::from_secs(15),
            Vec::new(),
        )
        .await
        .expect_err("a nonzero exit is refused");
        assert!(
            matches!(
                &refused,
                odin_domain::huginn::LiveError::Unavailable { code } if code == "zellij_action"
            ),
            "{refused:?}"
        );
        let pid = read_pid_file(&pid_path).await;
        assert!(wait_until_dead(pid).await, "the failed payload is stopped");
    }

    /// Z1: an action still queued for the blocking pool when its caller
    /// leaves never launches. The pool's sole thread is held busy, so the
    /// action is provably queued at the drop; a FIFO barrier on that thread
    /// then proves the refused action already ran.
    #[test]
    fn a_cancelled_queued_action_never_launches() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("runtime");
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let pid_path = root.join("queued.pid");
        let executable = payload(&root, &pid_path, "exit 0");
        let worker = launch_for_fixture(&executable);
        runtime.block_on(async {
            let (entered, entry) = tokio::sync::oneshot::channel();
            let (release, released) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).expect("entered");
                released.recv().expect("release");
            });
            entry.await.expect("pool occupied");
            let mut action = Box::pin(run_zellij(
                &executable,
                &worker,
                &root,
                Duration::from_secs(1),
                Vec::new(),
            ));
            assert!(futures_util::poll!(action.as_mut()).is_pending());
            drop(action);
            release.send(()).expect("release");
            blocker.await.expect("blocker");
            tokio::task::spawn_blocking(|| ()).await.expect("barrier");
            assert!(!pid_path.exists(), "the queued action never launches");
        });
    }

    /// Only `Stopped` disarms the guard; other outcomes retain a bounded drop retry.
    #[test]
    fn only_a_proved_stop_disarms_the_action_guard() {
        use odin_domain::{StopMissing, StopVerdict};
        let calls = std::cell::Cell::new(0);
        {
            let mut guard = super::ActionStopGuard {
                stop_worker: |_: &odin_types::WorkerId| {
                    calls.set(calls.get() + 1);
                    Ok(if calls.get() == 1 {
                        StopVerdict::Indeterminate(StopMissing {
                            reason: "transport lost".to_owned(),
                        })
                    } else {
                        StopVerdict::Stopped
                    })
                },
                worker_id: Some(odin_types::WorkerId::new("zellij-stop-retry").expect("worker")),
            };
            assert!(guard.stop().is_err(), "an unproved verdict is refused");
            assert!(guard.worker_id.is_some(), "and keeps the guard armed");
        }
        assert_eq!(calls.get(), 2, "the drop retries the unproved stop once");
        {
            let mut guard = super::ActionStopGuard {
                stop_worker: |_: &odin_types::WorkerId| {
                    calls.set(calls.get() + 1);
                    Ok(StopVerdict::Stopped)
                },
                worker_id: Some(odin_types::WorkerId::new("zellij-stop-proved").expect("worker")),
            };
            guard.stop().expect("a proved stop");
        }
        assert_eq!(calls.get(), 3, "a proved stop is never retried");
    }

    /// Both pipes drain inside the exit poll: a payload writing far past a
    /// pipe buffer before it exits finishes within its deadline, and its
    /// whole output comes back.
    #[tokio::test]
    async fn output_past_the_pipe_buffer_drains_while_the_action_runs() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().canonicalize().expect("root");
        let pid_path = root.join("payload.pid");
        let executable = payload(&root, &pid_path, "head -c 300000 /dev/zero");
        let worker = launch_for_fixture(&executable);
        let output = run_zellij(
            &executable,
            &worker,
            &root,
            Duration::from_secs(10),
            Vec::new(),
        )
        .await
        .expect("a large output drains");
        assert_eq!(output.len(), 300_000);
    }
}
