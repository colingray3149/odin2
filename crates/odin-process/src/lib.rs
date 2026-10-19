//! Shell-free Linux process isolation for Odin effects.

#![forbid(unsafe_code)]

mod argv;
mod environment;
mod error;
mod identity;
mod output;
mod runner;
mod systemd;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod worker;

pub use argv::FrozenArgv;
pub use environment::{AllowlistedEnvironment, EnvironmentBuilder};
pub use error::{ProcessError, ProcessErrorCode};
pub use identity::{
    IdentitySnapshot, MountIdentity, ProcessIdentity, ScanCriteria, SocketIdentity, SurvivorScanner,
};
pub use odin_types::WorkerId;
pub use output::CapturedOutput;
pub use runner::{
    CancellationToken, CommandSpec, ExitDisposition, ProcessControl, ProcessLaunch,
    ProcessLaunchRequest, ProcessLaunchResult, ProcessLimits, ProcessOutcome, ProcessStopEvidence,
    ProcessSupervisor, ProcessTransport, TeardownReport,
};
pub use systemd::{
    decode_body, marshal_method_call, marshal_value, parse_message, BusAddress, ManagerClient,
    Message, Value, MESSAGE_KIND_ERROR, MESSAGE_KIND_METHOD_CALL, MESSAGE_KIND_METHOD_RETURN,
    MESSAGE_KIND_SIGNAL,
};
pub use worker::{
    bootstrap_run, mint_worker_id, process_cgroup_line, scan_cgroup_residue, strip_bus_authority,
    RecoveryAnchors, RegisteredServiceBinding, ScopeLifetime, ScopeLimits, UnitIdentityProof,
    WorkerAuthority, WorkerChannel, WorkerError, WorkerErrorCode, WorkerIdentity, WorkerInspection,
    WorkerNaming, WorkerResidue, WorkerStdinWriter, WorkerStopReport, BOOTSTRAP_VAR,
    BUS_ADDRESS_VAR, BUS_AUTHORITY_ENV_VARS, STDIN_WRITE_TIMEOUT, UNSHARE_VAR,
};
pub const CORRELATION_ENV: &str = "ODIN_CORRELATION_ID";

/// The capsule is mounted at `/workspace/project`; namespaces and an empty environment isolate it.
pub fn capsule_sandbox_argv(
    bwrap: String,
    capsule_root: &std::path::Path,
    project_bind: &str,
) -> Vec<String> {
    vec![
        bwrap,
        "--new-session".to_owned(),
        "--unshare-all".to_owned(),
        "--clearenv".to_owned(),
        "--dir".to_owned(),
        "/workspace".to_owned(),
        project_bind.to_owned(),
        capsule_root.display().to_string(),
        "/workspace/project".to_owned(),
        "--dir".to_owned(),
        "/nix".to_owned(),
        "--ro-bind".to_owned(),
        "/nix/store".to_owned(),
        "/nix/store".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
    ]
}
