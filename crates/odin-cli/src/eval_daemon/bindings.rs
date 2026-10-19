//! Declared executable and environment bindings for registered session
//! workers: the worker launcher, launch specification, and sidecar ready
//! handshake.

use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_domain::Digest;
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_kernel::{ParentAuthorityClient, ParentBrokerServer, StopAuthority, PARENT_AUTHORITY_ENV};
use odin_process::{
    mint_worker_id, BusAddress, CommandSpec, EnvironmentBuilder, FrozenArgv,
    RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerChannel, WorkerNaming,
    CORRELATION_ENV,
};
use odin_types::CorrelationId;
use serde::Deserialize;

use super::provisioning::create_private_dir;

pub(super) const SIDE_CAR_STATE_BYTES: usize = 1_048_576;
pub(super) const SIDE_CAR_REQUESTS: u64 = 64;
pub(super) const SIDE_CAR_SPEND: u64 = 262_144;
pub(super) const READY_MAX_BYTES: usize = 4_096;
pub(super) const COMMAND_OUTPUT_MAX_BYTES: usize = 1_048_576;
const SANDBOX_TOOL_KEYS: [&str; 12] = [
    "cargo",
    "rustc",
    "rustdoc",
    "cc",
    "pkg-config",
    "bash",
    "jq",
    "b3sum",
    "git",
    "nix",
    "bun",
    "python3",
];
pub(super) const SIDE_CAR_READY_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn sandbox_tool_path(manifest: &RuntimeManifest) -> Result<String, String> {
    let mut directories = BTreeSet::new();
    for key in SANDBOX_TOOL_KEYS {
        let executable = manifest
            .executable(key)
            .map_err(|error| error.to_string())?;
        let directory = executable
            .path
            .parent()
            .ok_or_else(|| format!("runtime manifest {key} executable has no parent directory"))?;
        directories.insert(directory.to_path_buf());
    }
    let joined = env::join_paths(directories)
        .map_err(|error| format!("could not join sandbox PATH: {error}"))?;
    joined
        .into_string()
        .map_err(|_| "sandbox PATH is not valid UTF-8".to_owned())
}

#[derive(Clone)]
pub(crate) struct WorkerLauncher {
    pub(crate) authority: Arc<StopAuthority>,
    pub(super) nested: bool,
    attempt: Arc<AtomicU32>,
}

pub(crate) struct WorkerLaunchSpec<'a> {
    pub(crate) parent_broker: Option<&'a ParentBrokerServer>,
    pub(crate) executable_id: &'a str,
    pub(crate) role: &'a str,
    pub(crate) args: Vec<String>,
    pub(crate) environment: Vec<(String, String)>,
    pub(crate) current_dir: &'a Path,
    pub(crate) runtime_max: Duration,
}

impl WorkerLauncher {
    pub(crate) fn open(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
        authority_root: &Path,
    ) -> Result<Self, String> {
        Self::open_with_channel(config, manifest, authority_root, None)
    }

    pub(crate) fn open_with_channel(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
        authority_root: &Path,
        local_channel: Option<WorkerChannel>,
    ) -> Result<Self, String> {
        let parent = ParentAuthorityClient::from_env()
            .map_err(|error| format!("parent authority descriptor rejected: {error}"))?;
        let nested = parent.is_remote();
        let authority = if nested {
            let store_path = parent
                .expected_store_path()
                .map_err(|error| format!("scoped authority store rejected: {error}"))?;
            let ledger = odin_ledger::Ledger::open(&store_path)
                .map_err(|error| format!("could not open scoped authority ledger: {error}"))?;
            StopAuthority::from_parent(Arc::new(Mutex::new(ledger)), parent)
                .map_err(|error| format!("could not open scoped parent authority: {error}"))?
        } else {
            let store_root = authority_root.join("worker-authority");
            create_private_dir(&store_root)?;
            let store_path = store_root.join("ledger.sqlite3");
            let ledger = odin_ledger::Ledger::open(&store_path)
                .map_err(|error| format!("could not open eval worker ledger: {error}"))?;
            let channel = match local_channel {
                Some(channel) => channel,
                None => {
                    let bus = BusAddress::parse(&config.worker_bus)
                        .map_err(|error| format!("eval worker bus rejected: {error}"))?;
                    let bootstrap = manifest
                        .executable("worker_bootstrap")
                        .map_err(|error| format!("runtime manifest worker_bootstrap: {error}"))?;
                    let unshare = manifest
                        .executable("unshare")
                        .map_err(|error| format!("runtime manifest unshare: {error}"))?;
                    WorkerChannel::new(bus, bootstrap.path.clone(), unshare.path.clone())
                        .map_err(|error| format!("eval worker channel rejected: {error}"))?
                }
            };
            StopAuthority::new(Arc::new(Mutex::new(ledger)), channel)
        };
        Ok(Self {
            authority: Arc::new(authority),
            nested,
            attempt: Arc::new(AtomicU32::new(1)),
        })
    }

    pub(crate) fn launch(
        &self,
        manifest: &RuntimeManifest,
        spec: WorkerLaunchSpec<'_>,
    ) -> Result<(odin_kernel::stop::WorkerLaunch, CorrelationId), String> {
        let WorkerLaunchSpec {
            parent_broker,
            executable_id,
            role,
            args,
            mut environment,
            current_dir,
            runtime_max,
        } = spec;
        let executable = manifest
            .executable(executable_id)
            .map_err(|error| format!("runtime manifest {executable_id}: {error}"))?;
        let digest = executable
            .digest
            .strip_prefix("blake3:")
            .ok_or_else(|| format!("runtime manifest {executable_id} digest is not BLAKE3"))?;
        let binding = RegisteredServiceBinding::new(executable.path.clone(), digest.to_owned())
            .map_err(|error| format!("{executable_id} binding rejected: {error}"))?;
        let attempt = self.attempt.fetch_add(1, Ordering::Relaxed);
        let worker_id = mint_worker_id().map_err(|error| error.to_string())?;
        let correlation = correlation(&format!("{role}-{attempt}"))?;
        let naming = WorkerNaming::new(
            "odin-readmission",
            format!("eval-{role}"),
            attempt,
            worker_id.clone(),
        )
        .map_err(|error| format!("{role} worker naming rejected: {error}"))?;
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(executable.path.as_os_str().to_owned());
        argv.extend(args.into_iter().map(Into::into));
        let argv = FrozenArgv::new(argv, 128, 262_144)
            .map_err(|error| format!("{role} argv rejected: {error}"))?;
        if let Some(broker) = parent_broker {
            let descriptor = broker
                .prepare_scope(&worker_id)
                .map_err(|error| error.to_string())?;
            environment.push((
                PARENT_AUTHORITY_ENV.to_owned(),
                descriptor.to_environment_value(),
            ));
        }
        let mut keys = environment
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        keys.push(CORRELATION_ENV.to_owned());
        let mut builder = EnvironmentBuilder::new(keys.iter().map(String::as_str))
            .map_err(|error| format!("{role} environment rejected: {error}"))?;
        for (key, value) in environment {
            builder = builder
                .set(&key, &value)
                .map_err(|error| format!("{role} environment rejected: {error}"))?;
        }
        let environment = builder
            .set(CORRELATION_ENV, correlation.as_str())
            .map_err(|error| format!("{role} correlation environment rejected: {error}"))?
            .build();
        let spec = CommandSpec {
            argv,
            environment,
            current_dir: current_dir.to_path_buf(),
        };
        let launch = self
            .authority
            .launch_registered_service(
                naming,
                &correlation,
                &spec,
                ScopeLimits {
                    lifetime: ScopeLifetime::Bounded(runtime_max),
                    timeout_stop: Duration::from_secs(5),
                    ..ScopeLimits::default()
                },
                &binding,
            )
            .map_err(|error| format!("{role} registered launch failed: {error}"))?;
        if let Some(broker) = parent_broker {
            if let Err(error) = broker.activate_scope(&worker_id, &launch.identity) {
                let _ = self.authority.stop_worker(&worker_id);
                return Err(format!("session parent scope activation failed: {error}"));
            }
        }
        Ok((launch, correlation))
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadyRecord {
    schema: String,
    pub(super) socket_path: PathBuf,
}

pub(super) fn decode_ready(bytes: &[u8]) -> Result<ReadyRecord, String> {
    if bytes.len() > READY_MAX_BYTES || !bytes.ends_with(b"\n") {
        return Err("sidecar readiness is oversized or unterminated".to_owned());
    }
    let payload = &bytes[..bytes.len() - 1];
    let ready: ReadyRecord = odin_strict_json::decode(payload, READY_MAX_BYTES)
        .map_err(|error| format!("sidecar readiness rejected: {error}"))?;
    let canonical = odin_strict_json::canonicalize(&ready)
        .map_err(|error| format!("sidecar readiness canonicalization failed: {error}"))?;
    if canonical != payload || ready.schema != "OdinSidecarReady/v2" {
        return Err("sidecar readiness is not canonical OdinSidecarReady/v2".to_owned());
    }
    Ok(ready)
}

fn correlation(label: &str) -> Result<CorrelationId, String> {
    let digest = Digest::hash(format!("eval-daemon\0{label}").as_bytes()).to_string();
    let hex = digest
        .strip_prefix("blake3:")
        .ok_or_else(|| "correlation digest is not BLAKE3".to_owned())?;
    CorrelationId::new(&hex[..32]).map_err(|error| error.to_string())
}
