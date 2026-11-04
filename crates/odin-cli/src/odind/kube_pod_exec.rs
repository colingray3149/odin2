//! The kube transport of pod-exec capabilities: one fixed argv, and its
//! stdin when given, in a workload pod's worker container, reached the way
//! the pod browser relay reaches its pod (the run's UID-verified carrier).

use std::sync::Arc;
use std::time::Duration;

use odin_kube::exec::{run_in_worker, WorkloadExecError};
use odin_omp::host_tools::pod_exec::{PodWorkerExec, WorkerExecFault, WorkerOutput};

use super::KubeRuntimeCell;

pub(crate) struct KubePodWorkerExec {
    cell: Option<Arc<KubeRuntimeCell>>,
    runtime: tokio::runtime::Handle,
}

impl KubePodWorkerExec {
    pub fn new(cell: Option<Arc<KubeRuntimeCell>>) -> Self {
        Self {
            cell,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl PodWorkerExec for KubePodWorkerExec {
    fn exec(
        &self,
        run: &odin_domain::RunId,
        argv: &[String],
        stdin: Option<&[u8]>,
        wait: Duration,
        tail_bytes: usize,
    ) -> Result<WorkerOutput, WorkerExecFault> {
        let control = self
            .cell
            .as_ref()
            .and_then(|cell| cell.control())
            .ok_or_else(|| {
                WorkerExecFault::NotStarted("the k3s API server is unreachable".to_owned())
            })?;
        let client = control.reconciler().exec_client();
        let future = run_in_worker(&client, run, argv, stdin, wait, tail_bytes);
        // Host tools run on runtime workers; plain threads use the composition handle.
        let finished = match tokio::runtime::Handle::try_current() {
            Ok(current) => tokio::task::block_in_place(|| current.block_on(future)),
            Err(_) => self.runtime.block_on(future),
        };
        match finished {
            Ok(run) => Ok(WorkerOutput {
                exit_code: run.exit_code,
                stdout_tail: run.stdout_tail,
                stderr_tail: run.stderr_tail,
                stdout_bytes: run.stdout_bytes,
                stderr_bytes: run.stderr_bytes,
            }),
            Err(error @ WorkloadExecError::AttachFailed { .. }) => {
                Err(WorkerExecFault::Unknown(error.to_string()))
            }
            Err(error) => Err(WorkerExecFault::NotStarted(error.to_string())),
        }
    }
}
