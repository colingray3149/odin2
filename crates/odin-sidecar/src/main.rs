//! Receive launch credentials on stdin, report readiness on stdout, then serve the Unix socket.

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::env;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use odin_domain::extension_policy::ExtensionPolicyBinding;
use odin_domain::operation::Limits;
use odin_kernel::stop::{BusAddress, WorkerChannel};
use odin_kernel::ParentAuthorityClient;
use odin_sidecar::{
    AuthorityConfig, EffectorExecutor, EffectorSandboxBinding, InterpreterBinding, PeerCredentials,
    Provisioning, ServerConfig, Sidecar, SidecarError, SidecarErrorCode, SidecarServer,
    TransportProjection,
};
use odin_sidecar_protocol::{CapsuleBinding, WireLimits};
use odin_strict_json::canonicalize_to_writer;
use rustix::process::{getppid, pidfd_open, PidfdFlags};
use serde::Serialize;

const READY_SCHEMA: &str = "OdinSidecarReady/v2";

const KNOWN_FLAGS: &[&str] = &[
    "--state-root",
    "--socket-root",
    "--peer-pid",
    "--extension-policy",
    "--extension-policy-digest",
    "--accept-timeout-ms",
    "--projection-file",
    "--limits-requests",
    "--limits-stops",
    "--limits-spend",
    "--max-request-bytes",
    "--max-frame-bytes",
    "--max-state-bytes",
    "--effector",
    "--effector-digest",
    "--worker-bus",
    "--worker-bootstrap",
    "--worker-unshare",
    "--python-bin",
    "--bun-bin",
    "--capsule-id",
    "--capsule-root",
    "--source-commit",
    "--source-kind",
    "--git-bin",
    "--bwrap-bin",
    "--sandbox-cache-root",
    "--sandbox-tool-path",
    "--sandbox-context-root",
    "--cargo-registry-cache",
    "--cargo-git-cache",
    "--nix-config-root",
];

#[derive(Debug)]
struct Args {
    state_root: PathBuf,
    socket_root: PathBuf,
    peer_pid: i32,
    extension_policy: ExtensionPolicyBinding,
    accept_timeout_ms: u64,
    projection_file: PathBuf,
    limits_requests: u64,
    limits_stops: u64,
    limits_spend: u64,
    max_request_bytes: usize,
    max_frame_bytes: usize,
    max_state_bytes: usize,
    effector: PathBuf,
    effector_digest: String,
    worker_bus: Option<String>,
    worker_bootstrap: Option<PathBuf>,
    worker_unshare: Option<PathBuf>,
    python_bin: Option<PathBuf>,
    bun_bin: Option<PathBuf>,
    capsule_id: String,
    capsule_root: PathBuf,
    source_commit: String,
    source_kind: String,
    git_bin: PathBuf,
    bwrap_bin: Option<PathBuf>,
    sandbox_cache_root: Option<PathBuf>,
    sandbox_tool_path: Option<String>,
    sandbox_context_root: Option<PathBuf>,
    cargo_registry_cache: Option<PathBuf>,
    cargo_git_cache: Option<PathBuf>,
    nix_config_root: Option<PathBuf>,
}

#[derive(Serialize)]
struct ReadyRecord<'a> {
    schema: &'static str,
    socket_path: &'a Path,
}

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let outcome = collect_arguments().and_then(|input| {
        parse_args(&input).and_then(|args| run(args).map_err(|error| error.to_string()))
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!(%message, "odin-sidecar");
            ExitCode::FAILURE
        }
    }
}

fn collect_arguments() -> Result<Vec<String>, String> {
    env::args_os()
        .skip(1)
        .map(|argument| {
            argument
                .into_string()
                .map_err(|raw| format!("argument is not valid UTF-8: {raw:?}"))
        })
        .collect()
}

fn parse_args(input: &[String]) -> Result<Args, String> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let mut fields = input.iter();
    while let Some(flag) = fields.next() {
        if !KNOWN_FLAGS.contains(&flag.as_str()) {
            return Err(format!("unknown argument {flag}"));
        }
        let value = fields
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if is_flag_shaped(value) {
            return Err(format!("{flag} value {value:?} must not be flag-shaped"));
        }
        if pairs.iter().any(|(name, _)| *name == flag.as_str()) {
            return Err(format!("duplicate argument {flag}"));
        }
        pairs.push((flag.as_str(), value));
    }

    let worker_bus = optional(&pairs, "--worker-bus").map(ToOwned::to_owned);
    let worker_bootstrap = optional(&pairs, "--worker-bootstrap").map(PathBuf::from);
    let worker_unshare = optional(&pairs, "--worker-unshare").map(PathBuf::from);
    let worker_fields = [
        worker_bus.is_some(),
        worker_bootstrap.is_some(),
        worker_unshare.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if worker_fields != 0 && worker_fields != 3 {
        return Err(
            "--worker-bus, --worker-bootstrap, and --worker-unshare must appear together"
                .to_owned(),
        );
    }
    let python_bin = optional(&pairs, "--python-bin").map(PathBuf::from);
    let bun_bin = optional(&pairs, "--bun-bin").map(PathBuf::from);
    if python_bin.is_some() != bun_bin.is_some() {
        return Err("--python-bin and --bun-bin must appear together".to_owned());
    }
    let bwrap_bin = optional(&pairs, "--bwrap-bin").map(PathBuf::from);
    let sandbox_cache_root = optional(&pairs, "--sandbox-cache-root").map(PathBuf::from);
    let sandbox_tool_path = optional(&pairs, "--sandbox-tool-path").map(ToOwned::to_owned);
    let sandbox_required_fields = [
        bwrap_bin.is_some(),
        sandbox_cache_root.is_some(),
        sandbox_tool_path.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if sandbox_required_fields != 0 && sandbox_required_fields != 3 {
        return Err(
            "--bwrap-bin, --sandbox-cache-root, and --sandbox-tool-path must appear together"
                .to_owned(),
        );
    }
    Ok(Args {
        state_root: PathBuf::from(required(&pairs, "--state-root")?),
        socket_root: PathBuf::from(required(&pairs, "--socket-root")?),
        peer_pid: positive_pid(&pairs)?,
        extension_policy: ExtensionPolicyBinding::new(
            PathBuf::from(required(&pairs, "--extension-policy")?),
            required(&pairs, "--extension-policy-digest")?.to_owned(),
        ),
        accept_timeout_ms: nonzero_u64(&pairs, "--accept-timeout-ms")?,
        projection_file: PathBuf::from(required(&pairs, "--projection-file")?),
        limits_requests: numeric(&pairs, "--limits-requests")?,
        limits_stops: numeric(&pairs, "--limits-stops")?,
        limits_spend: numeric(&pairs, "--limits-spend")?,
        max_request_bytes: numeric(&pairs, "--max-request-bytes")?,
        max_frame_bytes: numeric(&pairs, "--max-frame-bytes")?,
        max_state_bytes: numeric(&pairs, "--max-state-bytes")?,
        effector: PathBuf::from(required(&pairs, "--effector")?),
        effector_digest: required(&pairs, "--effector-digest")?.to_owned(),
        worker_bus,
        worker_bootstrap,
        worker_unshare,
        python_bin,
        bun_bin,
        capsule_id: required(&pairs, "--capsule-id")?.to_owned(),
        capsule_root: PathBuf::from(required(&pairs, "--capsule-root")?),
        source_commit: required(&pairs, "--source-commit")?.to_owned(),
        source_kind: optional(&pairs, "--source-kind")
            .map(str::to_owned)
            .unwrap_or_else(|| "git-commit".to_owned()),
        git_bin: PathBuf::from(required(&pairs, "--git-bin")?),
        bwrap_bin,
        sandbox_cache_root,
        sandbox_tool_path,
        sandbox_context_root: optional(&pairs, "--sandbox-context-root").map(PathBuf::from),
        cargo_registry_cache: optional(&pairs, "--cargo-registry-cache").map(PathBuf::from),
        cargo_git_cache: optional(&pairs, "--cargo-git-cache").map(PathBuf::from),
        nix_config_root: optional(&pairs, "--nix-config-root").map(PathBuf::from),
    })
}

fn is_flag_shaped(value: &str) -> bool {
    value.starts_with('-')
}

fn run(args: Args) -> Result<(), SidecarError> {
    let parent_authority = ParentAuthorityClient::from_env().map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::Authority,
            format!("parent authority descriptor rejected: {error}"),
        )
    })?;
    let nested = parent_authority.is_remote();
    let parent_pidfd = open_parent_pidfd(args.peer_pid)?;
    if !nested {
        // Nested launch inserts a wrapper, so only direct launches require the peer to be the OS parent.
        require_parent_peer(args.peer_pid)?;
    }
    let policy = args.extension_policy.load().map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::Authority,
            format!("extension policy rejected: {error}"),
        )
    })?;
    policy
        .verify_extension_artifact(&policy.extension.path)
        .map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                format!("extension artifact rejected: {error}"),
            )
        })?;
    let operational = policy.sidecar;
    if args.accept_timeout_ms > operational.accept_timeout_ms
        || args.limits_requests > operational.max_requests
        || args.limits_spend > operational.max_spend
        || args.max_state_bytes as u64 > operational.max_state_bytes
        || args.max_request_bytes as u64 > operational.max_request_bytes
        || args.max_frame_bytes as u64 > operational.max_frame_bytes
    {
        return Err(SidecarError::new(
            SidecarErrorCode::Authority,
            "sidecar arguments widen the bound operational policy",
        ));
    }

    let projection_bytes = odin_sidecar::read_bounded(&args.projection_file, args.max_state_bytes)?;
    let projection = TransportProjection::from_bytes(&projection_bytes)?;
    if projection.snapshot_revision()
        != i64::try_from(policy.snapshot_revision).map_err(|_| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                "extension policy snapshot revision exceeds i64",
            )
        })?
    {
        return Err(SidecarError::new(
            SidecarErrorCode::Authority,
            "extension policy is stale against the provisioned snapshot",
        ));
    }
    // Keep launch credentials on stdin rather than exposing them through the environment or socket.
    let provisioning = Provisioning::read_from(&mut io::stdin().lock())?;

    let limits = Limits::new(args.limits_requests, args.limits_stops, args.limits_spend);
    let capsule = CapsuleBinding {
        capsule_id: args.capsule_id.clone(),
        root: args.capsule_root.display().to_string(),
        source_commit: args.source_commit.clone(),
        source_kind: args.source_kind.clone(),
        git_bin: args.git_bin.display().to_string(),
    };
    let executor = if nested {
        if args.worker_bus.is_some()
            || args.worker_bootstrap.is_some()
            || args.worker_unshare.is_some()
        {
            return Err(SidecarError::new(
                SidecarErrorCode::Authority,
                "nested sidecar must not receive worker bus/bootstrap/unshare arguments",
            ));
        }
        EffectorExecutor::new_nested(
            args.effector.clone(),
            args.effector_digest.clone(),
            capsule,
            odin_sidecar::system_clock(),
        )?
    } else {
        let worker_bus = args.worker_bus.as_deref().ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                "root-local sidecar requires --worker-bus",
            )
        })?;
        let worker_bootstrap = args.worker_bootstrap.clone().ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                "root-local sidecar requires --worker-bootstrap",
            )
        })?;
        let worker_unshare = args.worker_unshare.clone().ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                "root-local sidecar requires --worker-unshare",
            )
        })?;
        let bus = BusAddress::parse(worker_bus).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::Authority,
                format!("worker bus rejected: {error}"),
            )
        })?;
        let channel =
            WorkerChannel::new(bus, worker_bootstrap, worker_unshare).map_err(|error| {
                SidecarError::new(
                    SidecarErrorCode::Authority,
                    format!("worker channel rejected: {error}"),
                )
            })?;
        EffectorExecutor::new(
            args.effector.clone(),
            args.effector_digest.clone(),
            capsule,
            odin_sidecar::system_clock(),
            channel,
        )?
    };
    let executor = match (args.python_bin.clone(), args.bun_bin.clone()) {
        (Some(python), Some(bun)) => {
            executor.with_interpreters(InterpreterBinding::new(python, bun)?)
        }
        (None, None) => executor,
        _ => {
            return Err(SidecarError::new(
                SidecarErrorCode::Authority,
                "--python-bin and --bun-bin must appear together",
            ))
        }
    };
    let executor = match (
        args.bwrap_bin,
        args.sandbox_cache_root,
        args.sandbox_tool_path,
    ) {
        (Some(bwrap), Some(cache_root), Some(tool_path)) => {
            executor.with_sandbox(EffectorSandboxBinding::new(
                bwrap,
                cache_root,
                tool_path,
                args.sandbox_context_root,
                args.cargo_registry_cache,
                args.cargo_git_cache,
                args.nix_config_root,
            )?)
        }
        (None, None, None) => executor,
        _ => {
            return Err(SidecarError::new(
                SidecarErrorCode::Authority,
                "partial effector sandbox binding is forbidden",
            ))
        }
    };
    let config = AuthorityConfig::new(limits, args.max_state_bytes, executor)?;
    let sidecar = Sidecar::create_or_open(&args.state_root, config, projection, provisioning)?;

    let wire_limits = WireLimits::new(args.max_request_bytes, args.max_frame_bytes)?;
    let current = PeerCredentials::current();
    let expected_peer = PeerCredentials {
        pid: args.peer_pid,
        ..current
    };
    let server = SidecarServer::bind(
        &args.socket_root,
        sidecar,
        ServerConfig::new(wire_limits, expected_peer),
    )?;

    let ready = ReadyRecord {
        schema: READY_SCHEMA,
        socket_path: server.socket_path(),
    };
    let mut stdout = io::stdout().lock();
    canonicalize_to_writer(&ready, &mut stdout)
        .map_err(|error| SidecarError::new(SidecarErrorCode::Protocol, error.to_string()))?;
    stdout
        .write_all(b"\n")
        .map_err(|error| SidecarError::new(SidecarErrorCode::Protocol, error.to_string()))?;
    stdout
        .flush()
        .map_err(|error| SidecarError::new(SidecarErrorCode::Protocol, error.to_string()))?;

    server.accept_expected_until(&parent_pidfd, Duration::from_millis(args.accept_timeout_ms))
}

fn require_parent_peer(expected_pid: i32) -> Result<(), SidecarError> {
    let Some(parent) = getppid() else {
        return Err(SidecarError::new(
            SidecarErrorCode::Lifecycle,
            "sidecar process has no parent to serve",
        ));
    };
    if parent.as_raw_pid() != expected_pid {
        return Err(SidecarError::new(
            SidecarErrorCode::Lifecycle,
            format!(
                "--peer-pid {expected_pid} does not match the sidecar parent {}",
                parent.as_raw_pid()
            ),
        ));
    }
    Ok(())
}

fn open_parent_pidfd(expected_pid: i32) -> Result<OwnedFd, SidecarError> {
    let pid = rustix::process::Pid::from_raw(expected_pid).ok_or_else(|| {
        SidecarError::new(
            SidecarErrorCode::Lifecycle,
            format!("--peer-pid {expected_pid} is not a valid pid"),
        )
    })?;
    pidfd_open(pid, PidfdFlags::empty()).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::Lifecycle,
            format!("cannot open a pidfd for parent {expected_pid}: {error}"),
        )
    })
}

fn required<'a>(pairs: &[(&'a str, &'a str)], flag: &str) -> Result<&'a str, String> {
    pairs
        .iter()
        .find_map(|(name, value)| (*name == flag).then_some(*value))
        .ok_or_else(|| format!("missing required argument {flag}"))
}

fn optional<'a>(pairs: &[(&'a str, &'a str)], flag: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find_map(|(name, value)| (*name == flag).then_some(*value))
}

fn numeric<T>(pairs: &[(&str, &str)], flag: &str) -> Result<T, String>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw = required(pairs, flag)?;
    raw.parse::<T>()
        .map_err(|error| format!("{flag} value {raw:?} is malformed: {error}"))
}

fn positive_pid(pairs: &[(&str, &str)]) -> Result<i32, String> {
    let pid = numeric(pairs, "--peer-pid")?;
    if pid > 0 {
        Ok(pid)
    } else {
        Err("--peer-pid must be positive".to_string())
    }
}

fn nonzero_u64(pairs: &[(&str, &str)], flag: &str) -> Result<u64, String> {
    let value = numeric(pairs, flag)?;
    if value > 0 {
        Ok(value)
    } else {
        Err(format!("{flag} must be nonzero"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Vec<String> {
        [
            "--state-root",
            "/tmp/state",
            "--socket-root",
            "/tmp/sock",
            "--peer-pid",
            "4242",
            "--extension-policy",
            "/tmp/extension-policy.json",
            "--extension-policy-digest",
            "blake3:1111111111111111111111111111111111111111111111111111111111111111",
            "--accept-timeout-ms",
            "1000",
            "--projection-file",
            "/tmp/projection.json",
            "--limits-requests",
            "16",
            "--limits-stops",
            "4",
            "--limits-spend",
            "0",
            "--max-request-bytes",
            "262144",
            "--max-frame-bytes",
            "1048576",
            "--max-state-bytes",
            "65536",
            "--effector",
            "/store/odin-effector",
            "--effector-digest",
            "blake3:0000000000000000000000000000000000000000000000000000000000000000",
            "--worker-bus",
            "unix:path=/run/odin/worker-bus.sock",
            "--worker-bootstrap",
            "/store/odin-worker-bootstrap",
            "--worker-unshare",
            "/store/unshare",
            "--python-bin",
            "/store/python3",
            "--bun-bin",
            "/store/bun",
            "--capsule-id",
            "capsule-test",
            "--capsule-root",
            "/store/capsule",
            "--source-commit",
            "0123456789abcdef0123456789abcdef01234567",
            "--git-bin",
            "/store/git",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn parses_the_full_host_contract() {
        let args = parse_args(&base_args()).expect("full flag set parses");
        assert_eq!(args.peer_pid, 4242);
        assert_eq!(args.limits_requests, 16);
        assert_eq!(args.max_frame_bytes, 1_048_576);
        assert_eq!(args.effector, PathBuf::from("/store/odin-effector"));
        assert_eq!(
            args.effector_digest,
            "blake3:0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            args.worker_bus.as_deref(),
            Some("unix:path=/run/odin/worker-bus.sock")
        );
        assert_eq!(args.python_bin, Some(PathBuf::from("/store/python3")));
        assert_eq!(args.bun_bin, Some(PathBuf::from("/store/bun")));
        assert_eq!(args.capsule_id, "capsule-test");
        assert_eq!(
            args.source_commit,
            "0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_flag_shaped_values() {
        let mut unknown = base_args();
        unknown.push("--extra".to_owned());
        unknown.push("value".to_owned());
        assert!(parse_args(&unknown).is_err(), "unknown flags must fail");

        let mut duplicate = base_args();
        duplicate.push("--peer-pid".to_owned());
        duplicate.push("4243".to_owned());
        assert!(parse_args(&duplicate).is_err(), "duplicate flags must fail");

        let mut flag_shaped = base_args();
        flag_shaped.push("--source-commit".to_owned());
        flag_shaped.push("--tainted".to_owned());
        assert!(
            parse_args(&flag_shaped).is_err(),
            "flag-shaped values must fail"
        );
    }

    #[test]
    fn nested_shape_omits_all_worker_channel_flags() {
        let mut args = base_args();
        for flag in ["--worker-bus", "--worker-bootstrap", "--worker-unshare"] {
            let index = args
                .iter()
                .position(|value| value == flag)
                .expect("worker flag present");
            args.drain(index..=index + 1);
        }
        let parsed = parse_args(&args).expect("nested flag shape parses");
        assert!(parsed.worker_bus.is_none());
        assert!(parsed.worker_bootstrap.is_none());
        assert!(parsed.worker_unshare.is_none());
    }

    #[test]
    fn partial_worker_or_interpreter_bindings_fail_closed() {
        let mut worker = base_args();
        let worker_index = worker
            .iter()
            .position(|value| value == "--worker-unshare")
            .expect("worker flag present");
        worker.drain(worker_index..=worker_index + 1);
        assert!(parse_args(&worker).is_err(), "partial worker channel");

        let mut interpreter = base_args();
        let bun_index = interpreter
            .iter()
            .position(|value| value == "--bun-bin")
            .expect("bun flag present");
        interpreter.drain(bun_index..=bun_index + 1);
        assert!(parse_args(&interpreter).is_err(), "partial interpreters");
    }

    #[test]
    fn peer_pid_must_be_positive() {
        let mut zero = base_args();
        let index = zero
            .iter()
            .position(|value| value == "--peer-pid")
            .expect("flag present");
        zero[index + 1] = "0".to_owned();
        assert!(parse_args(&zero).is_err(), "peer pid zero must fail");
    }
}
