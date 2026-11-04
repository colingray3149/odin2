//! Workflow capabilities on the authority: the one `Ctx` odind builds (the
//! catalog and any pump share it), the compiled catalog, the runner that
//! launches every workflow process as a registered service of the authority
//! (so ohshit and the stop authority reach it), and Odin's own facts.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_domain::huginn::ObjectKind;
use odin_domain::StopVerdict;
use odin_hermes::runtime::HermesRuntime;
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_kernel::StopAuthority;
use odin_omp::host_tools::workflow::WorkflowBinding;
use odin_process::{RegisteredServiceBinding, ScopeLifetime, ScopeLimits, WorkerId};
use odin_types::CorrelationId;
use odin_workflows::config::ToolsConfig;
use odin_workflows::sandbox::{read_streams, RunFault, RunOutput, RunSpec, Runner};
use odin_workflows::{Catalog, Ctx, OdinFacts};
use serde_json::{json, Value};

use crate::composition::{open_stop_authority, registered_runtime_binding};
use crate::incidents::IncidentDesk;


/// The runtime-manifest key of the bubblewrap every workflow runs in.
const BWRAP_KEY: &str = "bwrap";
/// How long a stop, or an exit after the streams close, may take.
const SETTLE_WAIT: Duration = Duration::from_secs(5);
/// How long one stdin chunk may wait for the tool to read it.
const STDIN_WAIT: Duration = Duration::from_secs(30);
/// Between exit-status polls.
const EXIT_POLL: Duration = Duration::from_millis(20);
/// One stdin chunk.
const STDIN_CHUNK: usize = 64 * 1024;
/// The argv ceiling of one workflow process (bwrap options plus the tool's own).
const MAX_ARGS: usize = 1024;
const MAX_ARGV_BYTES: usize = 1024 * 1024;

/// The workflow binding of this daemon: compiled workflows when hermes is
/// composed (the authority), none elsewhere.
pub(crate) fn binding(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    hermes: Option<&Arc<HermesRuntime>>,
    incidents: &Arc<IncidentDesk>,
    read_model: &Arc<MaterializedReadModel>,
) -> Result<WorkflowBinding, String> {
    let Some(runtime) = hermes else {
        return Ok(WorkflowBinding { runner: None });
    };
    let (runner, bwrap) = RegisteredRunner::open(config, manifest)?;
    let facts = DaemonFacts {
        incidents: Arc::clone(incidents),
        read_model: Arc::clone(read_model),
    };
    let ctx = ctx(Arc::new(runner), bwrap)?.with_odin(Arc::new(facts));
    let catalog = Catalog::new(&odin_cli::runtime_bindings::workflow_families(), ctx)?;
    Ok(WorkflowBinding {
        runner: Some(odin_hermes::runtime::workflows::workflow_runner(
            runtime, catalog,
        )),
    })
}

/// The one Ctx odind builds; the catalog and any personal pump share it.
pub(crate) fn ctx(runner: Arc<dyn Runner>, bwrap: PathBuf) -> Result<Ctx, String> {
    Ok(Ctx::new(ToolsConfig::from_env()?, Some(bwrap), runner))
}

/// Launches each workflow's bwrap as a registered service of the authority.
struct RegisteredRunner {
    authority: Arc<StopAuthority>,
    binding: RegisteredServiceBinding,
    attempt: AtomicU32,
}

impl RegisteredRunner {
    fn open(config: &OdindConfig, manifest: &RuntimeManifest) -> Result<(Self, PathBuf), String> {
        let bwrap = manifest
            .executable(BWRAP_KEY)
            .map_err(|error| format!("runtime manifest {BWRAP_KEY}: {error}"))?
            .path
            .clone();
        let binding = registered_runtime_binding(manifest, BWRAP_KEY, &bwrap)?;
        let authority = open_stop_authority(
            manifest,
            &config.worker_bus,
            &config.paths.state_root.join("workflow-authority"),
            "workflow",
        )?;
        let runner = Self {
            authority,
            binding,
            attempt: AtomicU32::new(1),
        };
        Ok((runner, bwrap))
    }

    fn launch(&self, spec: &RunSpec) -> Result<odin_kernel::WorkerLaunch, String> {
        let worker_id = odin_process::mint_worker_id().map_err(|error| error.to_string())?;
        let correlation =
            CorrelationId::new(worker_id.as_str()).map_err(|error| error.to_string())?;
        let attempt = self.attempt.fetch_add(1, Ordering::Relaxed);
        let naming = odin_process::WorkerNaming::new("odind", "workflow", attempt, worker_id)
            .map_err(|error| error.to_string())?;
        let argv = odin_process::FrozenArgv::new(spec.argv.clone(), MAX_ARGS, MAX_ARGV_BYTES)
            .map_err(|error| format!("argv rejected: {error}"))?;
        let allowed = spec
            .env
            .iter()
            .map(|(key, _)| key.clone())
            .chain([odin_process::CORRELATION_ENV.to_owned()]);
        let mut environment = odin_process::EnvironmentBuilder::new(allowed)
            .and_then(|builder| builder.set(odin_process::CORRELATION_ENV, correlation.as_str()))
            .map_err(|error| format!("environment rejected: {error}"))?;
        for (key, value) in &spec.env {
            environment = environment
                .set(key, value)
                .map_err(|_| format!("environment variable {key} was rejected"))?;
        }
        let command = odin_process::CommandSpec {
            argv,
            environment: environment.build(),
            current_dir: PathBuf::from("/"),
        };
        let limits = ScopeLimits {
            lifetime: ScopeLifetime::Bounded(spec.timeout + SETTLE_WAIT),
            timeout_stop: SETTLE_WAIT,
            ..ScopeLimits::default()
        };
        self.authority
            .launch_registered_service(naming, &correlation, &command, limits, &self.binding)
            .map_err(|error| error.to_string())
    }

    /// Feeds the stdin file in the background, or closes stdin at once.
    fn feed_stdin(&self, worker: &WorkerId, stdin: Option<PathBuf>) {
        let Some(path) = stdin else {
            let _ = self.authority.close_worker_stdin(worker);
            return;
        };
        let (authority, worker) = (Arc::clone(&self.authority), worker.clone());
        std::thread::spawn(move || {
            if let Err(error) = write_stdin(&authority, &worker, &path) {
                tracing::warn!(
                    "workflow {worker} stdin {} stopped: {error}",
                    path.display()
                );
            }
            let _ = authority.close_worker_stdin(&worker);
        });
    }

    fn exit_code(&self, worker: &WorkerId) -> Result<Option<i32>, String> {
        let until = Instant::now() + SETTLE_WAIT;
        loop {
            match self.authority.try_wait_worker(worker) {
                Ok(Some(status)) => return Ok(status.code()),
                Ok(None) if Instant::now() < until => std::thread::sleep(EXIT_POLL),
                Ok(None) => return Err("it closed its output but did not exit".to_owned()),
                Err(error) => return Err(format!("its exit status is unreadable: {error}")),
            }
        }
    }
}

fn write_stdin(authority: &StopAuthority, worker: &WorkerId, path: &PathBuf) -> Result<(), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut buffer = vec![0; STDIN_CHUNK];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            return Ok(());
        }
        let mut sent = 0;
        while sent < read {
            sent += authority
                .write_worker_stdin_timeout(worker, &buffer[sent..read], STDIN_WAIT)
                .map_err(|error| error.to_string())?;
        }
    }
}

impl Runner for RegisteredRunner {
    fn run(&self, spec: &RunSpec, on_line: &mut dyn FnMut(&str)) -> Result<RunOutput, RunFault> {
        let launched = self.launch(spec).map_err(RunFault::NotStarted)?;
        let worker = launched.identity.worker_id.clone();
        self.feed_stdin(&worker, spec.stdin.clone());
        let streams = read_streams(launched.stdout, launched.stderr, spec, on_line);
        let code = if streams.timed_out {
            Ok(None)
        } else {
            self.exit_code(&worker)
        };
        match self
            .authority
            .stop_worker_bounded(&worker, Instant::now() + SETTLE_WAIT)
        {
            Ok(outcome) if outcome.verdict == StopVerdict::Stopped => {}
            Ok(outcome) => {
                return Err(RunFault::Lost(format!(
                    "its stop was not proved ({:?})",
                    outcome.verdict
                )))
            }
            Err(error) => return Err(RunFault::Lost(format!("its stop failed: {error}"))),
        }
        Ok(RunOutput {
            code: code.map_err(RunFault::Lost)?,
            timed_out: streams.timed_out,
            stdout: streams.stdout,
            stderr_tail: streams.stderr_tail,
        })
    }
}

/// Odin's own facts from what the daemon already holds: the incident desk's
/// open incidents and the read model's cluster and fleet objects.
struct DaemonFacts {
    incidents: Arc<IncidentDesk>,
    read_model: Arc<MaterializedReadModel>,
}

impl DaemonFacts {
    fn objects(&self, kinds: &[ObjectKind]) -> Value {
        match self.read_model.capture_kinds(kinds) {
            Ok(capture) => Value::Array(
                capture
                    .objects
                    .into_iter()
                    .map(|object| json!({ "id": object.object.id, "value": object.value }))
                    .collect(),
            ),
            Err(error) => {
                json!({ "unavailable": format!("the read model is unreadable: {error}") })
            }
        }
    }
}

impl OdinFacts for DaemonFacts {
    fn incidents(&self) -> Value {
        json!(self.incidents.open_views())
    }

    fn cluster(&self) -> Value {
        json!({
            "nodes": self.objects(&[ObjectKind::Node]),
            "resources": self.objects(&[ObjectKind::KubeResource]),
        })
    }

    fn fleet(&self) -> Value {
        self.objects(&[ObjectKind::FleetHost])
    }
}
