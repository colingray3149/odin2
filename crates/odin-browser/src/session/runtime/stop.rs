//! Stop browser resources within one deadline; keep profiles while a worker is still running.
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use odin_domain::{StopTraceEvent, StopVerdict};
use odin_kernel::stop::{StopOutcome, WorkerId};
use odin_kernel::StopAuthority;
use rustix::io::Errno;
use tokio::time::Instant;

use crate::relay::REMOTE_EXIT_EVIDENCE_MAX_BYTES;
use crate::worker::{Ack, EmptyParams, WorkerMethod};

use super::{BrowserRuntime, RuntimeTeardown, SessionError};
use crate::display::{display_accepts, x_lock_path, x_socket_path};

impl BrowserRuntime {
    pub(super) async fn shutdown_inner(&mut self) -> Result<RuntimeTeardown, SessionError> {
        let deadline = Instant::now() + self.shutdown_timeout;
        let profile_id = self
            .profile
            .as_ref()
            .map(|profile| profile.id().to_owned())
            .unwrap_or_default();
        let worker_owned = self.worker.is_some();
        let xvfb_owned = self.xvfb.is_some();
        let control_protocol_step = self.shutdown_timeout / 10;
        let close_protocol_step = self.shutdown_timeout / 5;
        let empty = EmptyParams {};

        let mut frame_producer_stopped = !self.frame_producer_started;
        if self.frame_producer_started {
            if let (Some(client), Some(budget)) = (
                self.client.as_ref(),
                step_budget(deadline, control_protocol_step),
            ) {
                frame_producer_stopped = matches!(
                    client
                        .call::<_, Ack>(WorkerMethod::StopFrames, &empty, budget)
                        .await,
                    Ok(Ack { acknowledged: true })
                );
            }
            self.frame_producer_started = false;
        }

        let mut browser_close_attempted = false;
        if self.browser_launched {
            if let (Some(client), Some(budget)) = (
                self.client.as_ref(),
                step_budget(deadline, close_protocol_step),
            ) {
                browser_close_attempted = true;
                let _ = client
                    .call::<_, Ack>(WorkerMethod::CloseBrowser, &empty, budget)
                    .await;
            }
            self.browser_launched = false;
        }

        if let (Some(client), Some(budget)) = (
            self.client.as_ref(),
            step_budget(deadline, control_protocol_step),
        ) {
            let _ = client
                .call::<_, Ack>(WorkerMethod::Shutdown, &empty, budget)
                .await;
        }
        self.client.take();

        let mut worker_channel_closed = false;
        if let Some(connection) = self.connection.take() {
            if let Some(budget) = step_budget(deadline, close_protocol_step) {
                worker_channel_closed = connection.close(budget).await.is_ok();
            }
        }

        // A relayed runtime owns no local process: the graceful remote stop
        // is the protocol ladder above plus the closed stdin half, and the
        // exit evidence is the transport's remote-status resolution within
        // the remaining budget. The carrier pod's lifecycle stays with the
        // kernel's stop authority, never with this teardown.
        if let Some(relayed) = self.relayed.take() {
            let mut exit_evidence = None;
            if let Some(exit) = relayed.exit.into_inner().map_err(|error| {
                SessionError::Shutdown(format!(
                    "read browser relay {} exit waiter: {error}",
                    relayed.identity
                ))
            })? {
                if let Some(budget) = step_budget(deadline, self.shutdown_timeout) {
                    exit_evidence = tokio::time::timeout(budget, exit).await.map_err(|error| {
                        SessionError::Shutdown(format!(
                            "wait for browser relay {} exit: {error}",
                            relayed.identity
                        ))
                    })?;
                }
            }
            let relayed_exit = exit_evidence.map(|evidence| {
                let mut bytes = evidence.into_bytes();
                bytes.truncate(REMOTE_EXIT_EVIDENCE_MAX_BYTES);
                String::from_utf8_lossy(&bytes).into_owned()
            });
            return Ok(RuntimeTeardown {
                profile_id,
                frame_producer_stopped,
                browser_close_attempted,
                worker_channel_closed,
                worker_owned: false,
                worker_term_sent: false,
                worker_kill_sent: false,
                worker_reaped: false,
                xvfb_owned: false,
                xvfb_term_sent: false,
                xvfb_kill_sent: false,
                xvfb_reaped: false,
                profile_removed: true,
                relayed_exit,
            });
        }

        let stop_budget = step_budget(deadline, self.shutdown_timeout.max(Duration::from_secs(1)));
        let worker_stop = match self.worker.take() {
            Some(worker) => match stop_budget {
                Some(budget) => {
                    let authority = Arc::clone(&self.host.authority);
                    let worker_id = worker.worker_id.clone();
                    match tokio::time::timeout(
                        budget,
                        tokio::task::spawn_blocking(move || stop_owned(&authority, &worker_id)),
                    )
                    .await
                    {
                        Ok(Ok(result)) => result?,
                        Ok(Err(error)) => {
                            return Err(SessionError::Shutdown(format!(
                                "join browser worker {} stop: {error}",
                                worker.worker_id
                            )))
                        }
                        Err(error) => {
                            return Err(SessionError::Shutdown(format!(
                                "wait for browser worker {} stop: {error}",
                                worker.worker_id
                            )))
                        }
                    }
                }
                None => {
                    return Err(SessionError::Shutdown(format!(
                        "stop browser worker {}: shutdown deadline expired",
                        worker.worker_id
                    )))
                }
            },
            None => ProcessStop::not_owned(),
        };

        let xvfb_stop = match self.xvfb.take() {
            Some(worker) => {
                let remaining =
                    step_budget(deadline, self.shutdown_timeout.max(Duration::from_secs(1)));
                let stop = match remaining {
                    Some(budget) => {
                        let authority = Arc::clone(&self.host.authority);
                        let worker_id = worker.worker_id.clone();
                        match tokio::time::timeout(
                            budget,
                            tokio::task::spawn_blocking(move || stop_owned(&authority, &worker_id)),
                        )
                        .await
                        {
                            Ok(Ok(result)) => result?,
                            Ok(Err(error)) => {
                                return Err(SessionError::Shutdown(format!(
                                    "join Xvfb worker {} stop: {error}",
                                    worker.worker_id
                                )))
                            }
                            Err(error) => {
                                return Err(SessionError::Shutdown(format!(
                                    "wait for Xvfb worker {} stop: {error}",
                                    worker.worker_id
                                )))
                            }
                        }
                    }
                    None => {
                        return Err(SessionError::Shutdown(format!(
                            "stop Xvfb worker {}: shutdown deadline expired",
                            worker.worker_id
                        )))
                    }
                };
                if stop.reaped {
                    if let Some(number) = self.owned_virtual_display.take() {
                        remove_owned_display_residue(number).map_err(|error| {
                            SessionError::Shutdown(format!(
                                "cannot remove owned virtual display :{number} residue: {error}"
                            ))
                        })?;
                    }
                }
                stop
            }
            None => ProcessStop::not_owned(),
        };

        if !worker_stop.reaped || !xvfb_stop.reaped {
            return Err(SessionError::Shutdown(format!(
                "owned workers not authoritatively absent (worker={}, xvfb={})",
                worker_stop.reaped, xvfb_stop.reaped
            )));
        }

        let profile_removed = if let Some(profile) = self.profile.take() {
            profile.remove()?;
            true
        } else {
            true
        };

        Ok(RuntimeTeardown {
            profile_id,
            frame_producer_stopped,
            browser_close_attempted,
            worker_channel_closed,
            worker_owned,
            worker_term_sent: worker_stop.term_sent,
            worker_kill_sent: worker_stop.kill_sent,
            worker_reaped: worker_stop.reaped,
            xvfb_owned,
            xvfb_term_sent: xvfb_stop.term_sent,
            xvfb_kill_sent: xvfb_stop.kill_sent,
            xvfb_reaped: xvfb_stop.reaped,
            profile_removed,
            relayed_exit: None,
        })
    }
}

impl Drop for BrowserRuntime {
    fn drop(&mut self) {
        // Keep profiles until the worker ledger confirms their processes stopped.
        for worker in [self.worker.take(), self.xvfb.take()].into_iter().flatten() {
            if let Err(error) = stop_owned(&self.host.authority, &worker.worker_id) {
                eprintln!(
                    "ERROR browser shutdown failed worker={} cause={error}",
                    worker.worker_id
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ProcessStop {
    pub(super) term_sent: bool,
    pub(super) kill_sent: bool,
    pub(super) reaped: bool,
}

impl ProcessStop {
    pub(super) const fn not_owned() -> Self {
        Self {
            term_sent: false,
            kill_sent: false,
            reaped: true,
        }
    }
}

fn stop_owned(
    authority: &StopAuthority,
    worker_id: &WorkerId,
) -> Result<ProcessStop, SessionError> {
    let outcome = authority.stop_worker(worker_id).map_err(|error| {
        SessionError::Shutdown(format!("stop browser worker {worker_id}: {error}"))
    })?;
    let stopped = process_stop_from_outcome(&outcome);
    if !stopped.reaped {
        return Err(SessionError::Shutdown(format!(
            "stop browser worker {worker_id}: {:?}",
            outcome.verdict
        )));
    }
    Ok(stopped)
}

pub(super) fn process_stop_from_outcome(outcome: &StopOutcome) -> ProcessStop {
    let term_sent = outcome
        .trace
        .iter()
        .any(|row| row.event == StopTraceEvent::Term);
    let kill_sent = outcome
        .trace
        .iter()
        .any(|row| row.event == StopTraceEvent::CgroupKill);
    let reaped = matches!(outcome.verdict, StopVerdict::Stopped)
        && outcome.evidence.leader_reaped
        && outcome.evidence.evidence_complete
        && outcome.evidence.cgroup_descendants == 0;
    ProcessStop {
        term_sent,
        kill_sent,
        reaped,
    }
}

fn step_budget(deadline: Instant, desired: Duration) -> Option<Duration> {
    let now = Instant::now();
    (now < deadline).then(|| (deadline - now).min(desired))
}

#[derive(Clone, Copy)]
struct ArtifactIdentity {
    device: u64,
    inode: u64,
}

impl ArtifactIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        self.device == metadata.dev() && self.inode == metadata.ino()
    }
}

fn remove_owned_display_residue(number: u16) -> io::Result<()> {
    if display_accepts(number, None) {
        return Err(io::Error::other(
            "display still accepts connections after owned Xvfb stop",
        ));
    }

    let socket = x_socket_path(number);
    let lock = x_lock_path(number);
    if lock_names_live_process(&lock)? {
        return Err(io::Error::other(
            "X lock still names a live process after owned Xvfb stop",
        ));
    }
    let lock_identity = inspect_owned_x_lock(&lock)?;
    let socket_identity = inspect_owned_x_socket(&socket)?;

    remove_verified_artifact(&socket, socket_identity)?;
    remove_verified_artifact(&lock, lock_identity)?;
    verify_artifact_absent(&socket)?;
    verify_artifact_absent(&lock)
}

fn lock_names_live_process(path: &Path) -> io::Result<bool> {
    let descriptor = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut file = File::from(descriptor);
    let mut contents = [0_u8; 32];
    let mut count = 0;
    while count < contents.len() {
        let read = file.read(&mut contents[count..])?;
        if read == 0 {
            break;
        }
        count += read;
    }
    let mut extra = [0_u8; 1];
    if count == contents.len() && file.read(&mut extra)? != 0 {
        return Err(io::Error::other("X lock contents exceed the safe bound"));
    }
    let Some(pid) = std::str::from_utf8(&contents[..count])
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
        .filter(|pid| *pid > 1)
    else {
        return Ok(false);
    };
    Ok(PathBuf::from(format!("/proc/{pid}")).exists())
}

fn inspect_owned_x_lock(path: &Path) -> io::Result<Option<ArtifactIdentity>> {
    let descriptor = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::other("X lock is not an owned regular file"));
    }
    Ok(Some(ArtifactIdentity::from_metadata(&metadata)))
}

fn inspect_owned_x_socket(path: &Path) -> io::Result<Option<ArtifactIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw() =>
        {
            Ok(Some(ArtifactIdentity::from_metadata(&metadata)))
        }
        Ok(_) => Err(io::Error::other("X socket is not an owned Unix socket")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn remove_verified_artifact(path: &Path, expected: Option<ArtifactIdentity>) -> io::Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match fs::symlink_metadata(path) {
        Ok(metadata) if expected.matches(&metadata) => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
        Ok(_) => Err(io::Error::other(
            "owned X display artifact changed before removal",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn verify_artifact_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other(
            "owned X display artifact remains after removal",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BrowserStopHost, Deadlines};
    use crate::session::runtime::RelayedRuntimeState;
    use odin_ledger::Ledger;
    use odin_process::{BusAddress, RegisteredServiceBinding, WorkerChannel};
    use std::sync::Mutex;

    #[tokio::test(start_paused = true)]
    async fn stalled_browser_exit_finishes_before_daemon_grace() {
        let executable = std::env::current_exe().expect("test executable");
        let binding =
            RegisteredServiceBinding::new(executable, "0".repeat(64)).expect("worker binding");
        let channel = WorkerChannel::for_recovery(
            BusAddress::parse("/tmp/browser-stop-test.sock").expect("bus address"),
        )
        .expect("worker channel");
        let host = BrowserStopHost {
            authority: Arc::new(StopAuthority::new(
                Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger"))),
                channel,
            )),
            tx_id: "browser-stop-test".into(),
            wp_id: "browser".into(),
            attempt: 1,
            worker_binding: binding,
        };
        let mut runtime = BrowserRuntime {
            host,
            profile: None,
            worker: None,
            xvfb: None,
            owned_virtual_display: None,
            client: None,
            connection: None,
            frame_producer_started: false,
            browser_launched: false,
            shutdown_timeout: Deadlines::default().shutdown,
            relayed: Some(RelayedRuntimeState {
                identity: "stalled-relay".into(),
                download_root: PathBuf::new(),
                exit: Mutex::new(Some(Box::pin(std::future::pending()))),
            }),
        };
        let result = tokio::time::timeout(Duration::from_secs(8), runtime.shutdown_inner())
            .await
            .expect("browser teardown must finish before the daemon grace");
        assert!(matches!(result, Err(SessionError::Shutdown(cause))
            if cause.contains("stalled-relay") && cause.contains("deadline")));
    }
}
