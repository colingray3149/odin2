//! Routes process operations through StopAuthority.

use std::sync::Arc;

use odin_domain::StopTraceEvent;
use odin_process::{
    ProcessControl, ProcessLaunch, ProcessLaunchRequest, ProcessLaunchResult, ProcessStopEvidence,
    WorkerError, WorkerErrorCode,
};
use odin_types::WorkerId;

use crate::{StopAuthority, StopAuthorityError};

pub struct StopAuthorityProcessTransport {
    authority: Arc<StopAuthority>,
}

impl StopAuthorityProcessTransport {
    pub fn new(authority: Arc<StopAuthority>) -> Self {
        Self { authority }
    }

    pub fn authority(&self) -> &Arc<StopAuthority> {
        &self.authority
    }
}

impl ProcessLaunch for StopAuthorityProcessTransport {
    fn launch(&self, request: ProcessLaunchRequest) -> Result<ProcessLaunchResult, WorkerError> {
        if request.worker_id != request.naming.worker_id {
            return Err(WorkerError::from_authority(
                WorkerErrorCode::ChannelInvalid,
                "process launch request worker id differs from its naming",
            ));
        }
        let launch = self
            .authority
            .launch_worker(
                request.naming,
                &request.correlation,
                &request.spec,
                request.scope_limits,
            )
            .map_err(|error| map_authority_error(error, WorkerErrorCode::Io))?;
        Ok(ProcessLaunchResult {
            identity: launch.identity,
            stdout: launch.stdout,
            stderr: launch.stderr,
        })
    }
}

impl ProcessControl for StopAuthorityProcessTransport {
    fn try_wait(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<std::process::ExitStatus>, WorkerError> {
        self.authority
            .try_wait_worker(worker_id)
            .map_err(|error| map_authority_error(error, WorkerErrorCode::Io))
    }

    fn stop(&self, worker_id: &WorkerId) -> Result<ProcessStopEvidence, WorkerError> {
        let outcome = self
            .authority
            .stop_worker(worker_id)
            .map_err(|error| map_authority_error(error, WorkerErrorCode::Stop))?;
        let term_sent = outcome
            .trace
            .iter()
            .any(|row| row.event == StopTraceEvent::Term);
        let cgroup_kill = outcome
            .trace
            .iter()
            .any(|row| row.event == StopTraceEvent::CgroupKill);
        Ok(ProcessStopEvidence {
            worker_id: outcome.worker_id,
            verdict: outcome.verdict,
            replay: outcome.replay,
            term_sent,
            cgroup_kill,
        })
    }
}

fn map_authority_error(error: StopAuthorityError, fallback: WorkerErrorCode) -> WorkerError {
    match error {
        StopAuthorityError::Worker(error) => error,
        error @ (StopAuthorityError::UnknownWorker(_)
        | StopAuthorityError::InvalidWorker(_)
        | StopAuthorityError::InvalidChannel(_)) => {
            WorkerError::from_authority(WorkerErrorCode::ChannelInvalid, error.to_string())
        }
        error => WorkerError::from_authority(fallback, error.to_string()),
    }
}
