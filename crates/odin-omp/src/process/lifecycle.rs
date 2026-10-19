//! Lifecycle draining, terminal exit recording, and best-effort Drop cleanup.

use std::process::ExitStatus;
use std::time::{Duration, Instant};

use crate::frames::MAX_REASSEMBLED_BYTES;

use odin_domain::{StopVerdict, StopVerdictTag};
use odin_kernel::StopAuthorityError;
use tokio::time::{sleep, timeout};

use super::streams::{join_drainer, snapshot_tail};
use super::*;

/// Maximum number of decoded frames retained by one bounded drain.
pub(crate) const DRAIN_FRAME_CAP: usize = 4096;

/// Maximum logical bytes retained by one bounded drain before the offending
/// frame is returned separately as exact overflow evidence.
pub(crate) const DRAIN_BYTE_CAP: usize = MAX_REASSEMBLED_BYTES;

/// Poll cadence while retaining nonterminal StopAuthority wait/stop.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);

impl OmpProcess {
    /// Returns the next decoded logical frame with its exact physical
    /// evidence.
    ///
    /// Blank lines and intra-sequence chunk frames are absorbed; one call
    /// yields exactly one logical frame. A cancelled call loses nothing: the
    /// partially accumulated physical frame lives in the process, so a resumed
    /// call continues it — a bridge still runs one dedicated read driver and
    /// marshals `send_json` through the same owner so frames stay ordered. At
    /// stdout EOF the decoder is finalized — an interrupted v2 chunk sequence
    /// rides in the exit record as evidence — and the child is driven
    /// to a terminal state and the exact exit record is returned as
    /// [`OmpProcessError::StdoutClosed`]; later calls replay it. A frame
    /// rejection or a physical over-ceiling line poisons the reader — the
    /// stream cannot resynchronize, so the same error is replayed for every
    /// subsequent call until the caller stops or kills the child.
    pub async fn next_frame(&mut self) -> Result<DecodedRpcFrame, OmpProcessError> {
        match self.state {
            OmpLifecycleState::Ready(_) | OmpLifecycleState::Draining => {}
            OmpLifecycleState::Exited => {
                let exit = self
                    .exit_record
                    .clone()
                    .ok_or(OmpProcessError::InvalidTransition {
                        operation: "next_frame",
                        from: self.state,
                    })?;
                return Err(OmpProcessError::StdoutClosed {
                    exit: Box::new(exit),
                });
            }
            from => {
                return Err(OmpProcessError::InvalidTransition {
                    operation: "next_frame",
                    from,
                })
            }
        }
        if let Some(poison) = self.poison.clone() {
            return Err(poison.into());
        }
        self.read_frame().await
    }

    /// Closes stdin, moving [`OmpLifecycleState::Ready`] into `Draining`.
    ///
    /// The child sees EOF and can finish; frames emitted afterwards stay
    /// readable through [`OmpProcess::next_frame`] and
    /// [`OmpProcess::graceful_stop`].
    pub fn close_stdin(&mut self) -> Result<(), OmpProcessError> {
        match self.state {
            OmpLifecycleState::Ready(_) => {
                self.close_owned_stdin()?;
                self.state = OmpLifecycleState::Draining;
                Ok(())
            }
            from => Err(OmpProcessError::InvalidTransition {
                operation: "close_stdin",
                from,
            }),
        }
    }

    /// Stops the child gracefully: closes stdin, drains stdout to EOF within
    /// the configured drain timeout, and returns every frame emitted during
    /// the drain plus the exact exit record.
    ///
    /// From `Draining` the drain continues; from `Exited` the retained record
    /// is returned with no frames. On drain timeout the error retains the
    /// frames read so far and leaves the child for the caller — graceful stop
    /// never escalates on its own; call [`OmpProcess::kill`] or drop.
    pub async fn graceful_stop(&mut self) -> Result<OmpShutdown, OmpProcessError> {
        match self.state {
            OmpLifecycleState::Exited => {
                let exit = self
                    .exit_record
                    .clone()
                    .ok_or(OmpProcessError::InvalidTransition {
                        operation: "graceful_stop",
                        from: self.state,
                    })?;
                return Ok(OmpShutdown {
                    frames: Vec::new(),
                    exit,
                });
            }
            OmpLifecycleState::Ready(_) => {
                self.close_owned_stdin()?;
                self.state = OmpLifecycleState::Draining;
            }
            OmpLifecycleState::Draining => {}
            from => {
                return Err(OmpProcessError::InvalidTransition {
                    operation: "graceful_stop",
                    from,
                })
            }
        }
        let deadline = Instant::now() + self.spec.drain_timeout;
        let mut frames = Vec::new();
        let mut retained_bytes = 0usize;
        loop {
            let budget = deadline.saturating_duration_since(Instant::now());
            match timeout(budget, self.read_frame()).await {
                Ok(Ok(frame)) => {
                    let next_bytes = retained_bytes.saturating_add(frame.raw().len());
                    if frames.len() >= DRAIN_FRAME_CAP || next_bytes > DRAIN_BYTE_CAP {
                        return Err(OmpProcessError::DrainLimit {
                            frames,
                            bytes: retained_bytes,
                            overflow: Box::new(frame),
                        });
                    }
                    retained_bytes = next_bytes;
                    frames.push(frame);
                }
                Ok(Err(OmpProcessError::StdoutClosed { exit })) => {
                    return Ok(OmpShutdown {
                        frames,
                        exit: *exit,
                    });
                }
                Ok(Err(error)) => return Err(error),
                Err(_elapsed) => return Err(OmpProcessError::DrainTimeout { frames }),
            }
        }
    }

    /// Stops through StopAuthority; incomplete cleanup remains retryable.
    pub async fn kill(&mut self) -> Result<OmpExitRecord, OmpProcessError> {
        if self.state == OmpLifecycleState::Stopped {
            return Err(OmpProcessError::InvalidTransition {
                operation: "kill",
                from: self.state,
            });
        }
        if self.state == OmpLifecycleState::Exited {
            let record = self
                .exit_record
                .clone()
                .ok_or(OmpProcessError::InvalidTransition {
                    operation: "kill",
                    from: self.state,
                })?;
            return Ok(record);
        }
        self.begin_reaping(None);
        self.force_reap().await
    }

    /// Waits briefly after EOF before stopping locally or requiring remote escalation.
    pub(super) async fn observe_exit(
        &mut self,
        budget: Duration,
        unfinished: Option<RpcFrameError>,
    ) -> Result<OmpExitRecord, OmpProcessError> {
        self.begin_reaping(unfinished);
        match self.carrier {
            HarnessCarrier::Local => {
                if self.pending_status.is_none() {
                    match self.wait_status(budget).await {
                        Ok(Some(status)) => self.pending_status = Some(status),
                        Ok(None) => return self.force_reap().await,
                        Err(detail) => return Err(self.reap_incomplete(detail)),
                    }
                }
                self.finish_reap().await
            }
            HarnessCarrier::Remote { .. } => self.observe_remote_exit(budget).await,
        }
    }

    /// Remote EOF needs a terminal transport status; otherwise the caller must stop the Job.
    async fn observe_remote_exit(
        &mut self,
        budget: Duration,
    ) -> Result<OmpExitRecord, OmpProcessError> {
        let waiter = self.remote_exit_waiter.take().ok_or_else(|| {
            self.reap_incomplete("the remote carrier carries no terminal status waiter")
        })?;
        match timeout(budget, waiter).await {
            Ok(exit) => {
                let proved = exit.clean || exit.status.is_some();
                let evidence = OmpRemoteExit::from_transport(exit);
                if !proved {
                    return Err(self.reap_incomplete(format!(
                        "remote carrier closed without terminal status: {}",
                        evidence.failure().unwrap_or("no status reported")
                    )));
                }
                let unfinished = self.pending_unfinished.take();
                Ok(self.record_exit(None, unfinished, Some(evidence)).await)
            }
            Err(_elapsed) => Err(self.reap_incomplete(
                "the remote carrier produced no terminal status within the drain budget",
            )),
        }
    }

    /// Closes command admission while retaining unfinished decoder data for the exit record.
    pub(super) fn begin_reaping(&mut self, unfinished: Option<RpcFrameError>) {
        if let Err(error) = self.close_owned_stdin() {
            let worker = match &self.carrier {
                HarnessCarrier::Local => self.worker_id.as_ref().map(WorkerId::as_str),
                HarnessCarrier::Remote { job_worker, .. } => Some(job_worker.as_str()),
            };
            tracing::error!(
                worker = worker.unwrap_or("unassigned"),
                operation = "close_stdin",
                cause = %error,
                "OMP stdin close failed; continuing stop"
            );
        }
        if self.pending_unfinished.is_none() {
            self.pending_unfinished = unfinished;
        }
        if self.state != OmpLifecycleState::Exited {
            self.state = OmpLifecycleState::Draining;
        }
    }

    /// Stops the worker without requiring a root exit status first.
    pub(super) async fn force_reap(&mut self) -> Result<OmpExitRecord, OmpProcessError> {
        if matches!(self.carrier, HarnessCarrier::Local) && self.pending_status.is_none() {
            match self.wait_status(Duration::from_millis(1)).await {
                Ok(Some(status)) => self.pending_status = Some(status),
                Ok(None) => {}
                Err(error) => tracing::error!(
                    worker = ?self.worker_id,
                    operation = "wait_status",
                    cause = %error,
                    "OMP exit status unavailable; continuing stop"
                ),
            }
        }
        self.finish_reap().await
    }

    /// Records an exit only after the local worker or remote Job has stopped.
    async fn finish_reap(&mut self) -> Result<OmpExitRecord, OmpProcessError> {
        let remote = match self.carrier {
            HarnessCarrier::Local => {
                let outcome = self.stop_owned().await?;
                match outcome.verdict {
                    StopVerdict::Stopped => {}
                    other => {
                        return Err(self.reap_incomplete(format!(
                            "stop verdict was {other:?}; refused to mint a stopped record"
                        )))
                    }
                }
                if self.pending_status.is_none() {
                    match self.wait_status(Duration::from_millis(1)).await {
                        Ok(Some(status)) => self.pending_status = Some(status),
                        Ok(None) => {}
                        Err(error) => tracing::error!(
                            worker = ?self.worker_id,
                            operation = "wait_status",
                            cause = %error,
                            "OMP exit status unavailable after stop"
                        ),
                    }
                }
                None
            }
            HarnessCarrier::Remote { .. } => Some(self.stop_remote().await?),
        };
        let unfinished = self.pending_unfinished.take();
        let status = self.pending_status.take();
        Ok(self.record_exit(status, unfinished, remote).await)
    }

    /// Stops the remote Job using its bound action rather than killing the exec channel.
    async fn stop_remote(&mut self) -> Result<OmpRemoteExit, OmpProcessError> {
        let (job_worker, action) = match &self.carrier {
            HarnessCarrier::Remote {
                job_worker,
                stop_action,
            } => (job_worker.clone(), *stop_action),
            HarnessCarrier::Local => {
                return Err(self.reap_incomplete("local carriers cannot stop a remote Job"))
            }
        };
        let authority = Arc::clone(&self.worker.authority);
        let outcome = match timeout(
            self.spec.kill_timeout,
            tokio::task::spawn_blocking(move || authority.stop_job_worker(&job_worker, action)),
        )
        .await
        {
            Ok(Ok(Ok(outcome))) => outcome,
            Ok(Ok(Err(error))) => {
                return Err(self.reap_incomplete(format!("remote stop request failed: {error}")))
            }
            Ok(Err(error)) => {
                return Err(
                    self.reap_incomplete(format!("remote stop task failed to join: {error}"))
                )
            }
            Err(_) => {
                return Err(self.reap_incomplete("remote stop exceeded the configured kill timeout"))
            }
        };
        match outcome.verdict {
            StopVerdictTag::Stopped => Ok(OmpRemoteExit::stopped()),
            StopVerdictTag::Failed => Err(self.reap_incomplete(format!(
                "remote stop failed: job_absent={}, {} pod(s) survived",
                outcome.evidence.job_absent,
                outcome.evidence.pod_residue.len()
            ))),
            other => {
                Err(self.reap_incomplete(format!("remote stop incomplete (verdict {other:?})")))
            }
        }
    }

    /// Runs the blocking authority stop without holding a shared borrow of the streams.
    async fn stop_owned(&mut self) -> Result<odin_kernel::stop::StopOutcome, OmpProcessError> {
        let worker_id = self
            .worker_id
            .clone()
            .ok_or_else(|| self.reap_incomplete("logical worker id is missing"))?;
        let authority = Arc::clone(&self.worker.authority);
        let id = worker_id.clone();
        match timeout(
            self.spec.kill_timeout,
            tokio::task::spawn_blocking(move || authority.stop_worker(&id)),
        )
        .await
        {
            Ok(Ok(Ok(outcome))) => Ok(outcome),
            Ok(Ok(Err(error))) => Err(self.reap_incomplete(error.to_string())),
            Ok(Err(error)) => Err(self.reap_incomplete(format!("stop task failed: {error}"))),
            Err(_) => Err(self
                .reap_incomplete("StopAuthority stop_worker exceeded the configured kill timeout")),
        }
    }

    /// Polls `try_wait_worker` so timeout cancellation never abandons an
    /// in-progress wait or loses a subsequently observable status.
    async fn wait_status(&mut self, budget: Duration) -> Result<Option<ExitStatus>, String> {
        if let Some(status) = self.pending_status {
            return Ok(Some(status));
        }
        let Some(worker_id) = self.worker_id.clone() else {
            return Err("logical worker id is missing before waiting for exit".to_owned());
        };
        let deadline = Instant::now() + budget;
        loop {
            match self.worker.authority.try_wait_worker(&worker_id) {
                Ok(Some(status)) => return Ok(Some(status)),
                Ok(None) => {}
                Err(StopAuthorityError::UnknownWorker(_)) => return Ok(None),
                Err(error) => return Err(format!("observing root exit status failed: {error}")),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            sleep(REAP_POLL_INTERVAL.min(remaining)).await;
        }
    }

    fn reap_incomplete(&self, detail: impl Into<String>) -> OmpProcessError {
        let worker_id = match self.worker_id.as_ref() {
            Some(worker_id) => worker_id.as_str().to_owned(),
            None => match &self.carrier {
                HarnessCarrier::Remote { job_worker, .. } => job_worker.as_str().to_owned(),
                HarnessCarrier::Local => "unassigned".to_owned(),
            },
        };
        OmpProcessError::ReapIncomplete {
            root_reaped: self.pending_status.is_some(),
            worker_id,
            detail: detail.into(),
        }
    }

    /// Joins stderr after teardown, then discards streams and retains the exit.
    async fn record_exit(
        &mut self,
        status: Option<ExitStatus>,
        unfinished: Option<RpcFrameError>,
        remote: Option<OmpRemoteExit>,
    ) -> OmpExitRecord {
        if let Some(drainer) = self.stderr_task.take() {
            join_drainer(drainer, self.spec.kill_timeout).await;
        }
        self.worker_id = None;
        self.stdin = None;
        self.stdout = None;
        self.remote_exit_waiter = None;
        let record = OmpExitRecord {
            status,
            stderr_tail: snapshot_tail(&self.stderr_tail),
            unfinished,
            remote,
        };
        self.exit_record = Some(record.clone());
        self.state = OmpLifecycleState::Exited;
        record
    }
}

impl Drop for OmpProcess {
    /// Stops abandoned workers off-thread, falling back synchronously if spawning fails.
    fn drop(&mut self) {
        let authority = Arc::clone(&self.worker.authority);
        match &self.carrier {
            HarnessCarrier::Remote {
                job_worker,
                stop_action,
            } => {
                if self.state == OmpLifecycleState::Exited {
                    return;
                }
                let id = job_worker.clone();
                let action = *stop_action;
                let retry_id = id.clone();
                match std::thread::Builder::new()
                    .name("odin-omp-stop".to_owned())
                    .spawn(move || {
                        drop_stop_job(&authority, &id, action);
                    }) {
                    Ok(handle) => drop(handle),
                    Err(error) => {
                        tracing::error!(
                            worker = retry_id.as_str(),
                            operation = "spawn_drop_stop_thread",
                            cause = %error,
                            "OMP cleanup thread failed; stopping synchronously"
                        );
                        drop_stop_job(&self.worker.authority, &retry_id, action);
                    }
                }
                return;
            }
            HarnessCarrier::Local => {}
        }
        let Some(worker_id) = self.worker_id.take() else {
            return;
        };
        #[cfg(test)]
        let test_fixture = self.worker._test_fixture.clone();
        let id = worker_id.clone();
        match std::thread::Builder::new()
            .name("odin-omp-stop".to_owned())
            .spawn(move || {
                drop_stop_worker(&authority, &id);
                #[cfg(test)]
                {
                    drop(authority);
                    drop(test_fixture);
                }
            }) {
            Ok(handle) => drop(handle),
            Err(error) => {
                tracing::error!(
                    worker = worker_id.as_str(),
                    operation = "spawn_drop_stop_thread",
                    cause = %error,
                    "OMP cleanup thread failed; stopping synchronously"
                );
                drop_stop_worker(&self.worker.authority, &worker_id);
            }
        }
    }
}

fn drop_stop_worker(authority: &StopAuthority, worker_id: &WorkerId) {
    match authority.stop_worker(worker_id) {
        Ok(outcome) if outcome.verdict == StopVerdict::Stopped => {}
        Ok(outcome) => tracing::error!(
            worker = worker_id.as_str(),
            operation = "stop_worker",
            cause = ?outcome.verdict,
            "OMP Drop cleanup incomplete"
        ),
        Err(error) => tracing::error!(
            worker = worker_id.as_str(),
            operation = "stop_worker",
            cause = %error,
            "OMP Drop cleanup failed"
        ),
    }
}

fn drop_stop_job(authority: &StopAuthority, worker_id: &WorkerId, action: JobStopAction) {
    match authority.stop_job_worker(worker_id, action) {
        Ok(outcome) if outcome.verdict == StopVerdictTag::Stopped => {}
        Ok(outcome) => tracing::error!(
            worker = worker_id.as_str(),
            operation = "stop_job_worker",
            action = action.as_str(),
            cause = ?outcome.verdict,
            job_absent = outcome.evidence.job_absent,
            surviving_pods = ?outcome.evidence.pod_residue,
            faults = ?outcome.evidence.fault_probes,
            "OMP Drop cleanup incomplete"
        ),
        Err(error) => tracing::error!(
            worker = worker_id.as_str(),
            operation = "stop_job_worker",
            action = action.as_str(),
            cause = %error,
            "OMP Drop cleanup failed"
        ),
    }
}
