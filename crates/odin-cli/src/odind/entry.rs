//! Argument/entry dispatch for the `odind` binary: the clap surface, the
//! subcommand handlers, and the report writers they share.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use odin_cli::omp_conformance;
use odin_huginn::OdindConfig;

use crate::controller;
use crate::live::serving::serve_huginn;
use crate::projection::check_serving_composition;

#[derive(Debug, Parser)]
#[command(
    name = "odind",
    version,
    about = "Odin controller",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub(super) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate controller startup against the strict generated config;
    /// `--config-only` runs only the strict config parse and validation.
    Check(CheckArgs),
    /// Generate the served gateway projection from declarations: the pinned
    /// catalog stays the provider-lane fact source and every composed
    /// workload surface derives its route row. Prints the digest to pin.
    GatewayProjection(GenerateGatewayProjectionArgs),
    /// Mount the private Huginn/ColinRemote service on the controller runtime.
    Huginn(HuginnArgs),
    /// Govern one declared archive knowledge source: mint the exact-scope
    /// R3 demand (prepare), consume the operator approval and run the
    /// bounded ingest (ingest), inspect the persisted serving state
    /// (status), or fill the declared embedding lane (backfill).
    Archive(crate::archive::ArchiveArgs),
    /// Inspect durable conversation delivery or reconcile one confirmed applied operation.
    Delivery(crate::delivery::DeliveryArgs),
    /// Run the pinned OMP probe suite and write the observation report.
    OmpConformance(OmpConformanceArgs),
    /// Internal workload carrier boundary: verify the staged extension
    /// policy and the pinned extension bytes in-pod, then exec the declared
    /// launcher over this process. Never a model surface.
    #[command(hide = true)]
    WorkloadExec(WorkloadExecArgs),
    /// Internal passive carrier boundary: the workload pod's init parks on
    /// signal delivery only — no launcher runs before attach, no periodic
    /// work — reaps the children the runtime reparents to it, and exits
    /// cleanly under the pod-level stop. Never a model surface.
    #[command(hide = true)]
    WorkloadPark,
    /// Internal pod browser PID 1: serve one display and worker through the
    /// private relay socket, then tear down the namespace. Never a model surface.
    #[command(hide = true)]
    BrowserServe(BrowserServeArgs),
    /// Internal pod browser attach: the host-exec'd one-use activation and
    /// byte bridge to the container-private relay socket. Never a model
    /// surface.
    #[command(hide = true)]
    BrowserConnect(BrowserConnectArgs),
}

#[derive(Debug, Args)]
struct BrowserServeArgs {
    /// Absolute in-image path of the pinned node executable.
    #[arg(long, value_name = "PATH")]
    node: PathBuf,
    /// Absolute in-image path of the declared Xvfb executable.
    #[arg(long, value_name = "PATH")]
    xvfb: PathBuf,
    /// Virtual display geometry `<width>x<height>x<depth>`.
    #[arg(long, value_name = "WxHxD")]
    screen: String,
    /// The per-browser-container state dir under the declared state mount.
    #[arg(long, value_name = "DIR")]
    state_dir: PathBuf,
    /// The container-private relay socket path.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,
}

#[derive(Debug, Args)]
struct BrowserConnectArgs {
    /// The container-private relay socket path.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,
    /// The live session identity this one-use activation carries.
    #[arg(long, value_name = "UUID")]
    session: String,
}

#[derive(Debug, Args)]
struct WorkloadExecArgs {
    /// Absolute in-pod path of the staged read-only policy document.
    #[arg(long, value_name = "PATH")]
    extension_policy: PathBuf,
    /// The journaled policy binding digest (`blake3:<64 hex>`).
    #[arg(long, value_name = "DIGEST")]
    extension_policy_digest: String,
    /// Absolute in-pod path of the staged read-only models document.
    #[arg(long, value_name = "PATH")]
    models_config: PathBuf,
    /// The journaled models document digest (`blake3:<64 hex>`).
    #[arg(long, value_name = "DIGEST")]
    models_config_digest: String,
    /// The unique per-run agent dir under the declared state mount; bound
    /// as `PI_CODING_AGENT_DIR` for the launcher.
    #[arg(long, value_name = "DIR")]
    agent_dir: PathBuf,
    /// The declared state mount the agent dir lives under: the confined
    /// root every agent-dir component is created and sealed beneath.
    #[arg(long, value_name = "PATH")]
    state_mount: PathBuf,
    /// The carrier env NAME the models document names as the provider
    /// `apiKey`; it must be present and non-empty before any exec.
    #[arg(long, value_name = "NAME")]
    credential_env: String,
    /// The explicit working directory the launcher execs under.
    #[arg(long, value_name = "PATH")]
    working_dir: PathBuf,
    /// Absolute in-image path of the declared extension entrypoint.
    #[arg(long, value_name = "PATH")]
    trusted_extension: PathBuf,
    /// The declared launcher argv, passed through verbatim.
    #[arg(last = true)]
    launcher_argv: Vec<String>,
}

#[derive(Debug, Args)]
struct ConfigPathArgs {
    /// Strict Nix-generated `odind.toml`; the only constructor input.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// Restrict the check to the strict config parse and validation: no
    /// registry snapshot, durable state, or network prerequisite.
    #[arg(long)]
    config_only: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GenerateGatewayProjectionArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// Absent output path for the canonical projection file; never clobbered.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct HuginnArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
}

#[derive(Debug, Args)]
struct BackupArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// Required absent output directory for an offline backup set; never
    /// clobbered. Must lie outside every captured root. Managed retention
    /// is available only through pc-publish.
    #[arg(long, value_name = "DIR")]
    output: PathBuf,
    /// Operator attestation that the supervisor and every writer of the
    /// captured roots are stopped and disabled. Attestation only — never
    /// proof of fencing; capture stability is verified separately.
    #[arg(long)]
    quiesced: bool,
}

#[derive(Debug, Args)]
struct BackupVerifyArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// Managed backup root containing the current symlink.
    #[arg(long, value_name = "PATH")]
    root: PathBuf,
}

#[derive(Debug, Args)]
struct RestoreDrillArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// Backup-set directory produced by `odind backup`.
    #[arg(long, value_name = "DIR")]
    backup: PathBuf,
    /// Absent disposable destination directory; restore never overwrites.
    #[arg(long, value_name = "DIR")]
    destination: PathBuf,
    /// Explicit offline privileged RustiCal install into an absent directory.
    /// Stop RustiCal and all writers first; restores the manifest owner/group.
    #[arg(long, value_name = "DIR")]
    install_rustical: Option<PathBuf>,
    /// Report output path for the restore-drill verdict.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct AuthorityRehearsalArgs {
    #[arg(long, value_name = "PATH")]
    before_registry: PathBuf,
    #[arg(long, value_name = "PATH")]
    after_registry: PathBuf,
    #[arg(long, value_name = "PATH")]
    state_root: PathBuf,
    #[arg(long, value_name = "ID")]
    old_node: String,
    #[arg(long, value_name = "ID")]
    new_node: String,
    #[arg(long, required = true)]
    json: bool,
}

#[derive(Debug, Args)]
struct OmpConformanceArgs {
    #[command(flatten)]
    config_args: ConfigPathArgs,
    /// Disposable fixture work root that retains suite evidence.
    #[arg(long, value_name = "DIR")]
    fixture_root: PathBuf,
    /// Canonical OMP conformance report path.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

pub(super) fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Check(arguments) => {
            let config = load_config(&arguments.config_args.config)?;
            if arguments.config_only {
                // The strict parse and validation above is the whole
                // scope; registry, state, and network stay untouched.
                return write_report(
                    &ConfigCheckReport {
                        schema: CONFIG_CHECK_SCHEMA,
                        config: arguments.config_args.config.to_string_lossy().into_owned(),
                        config_schema: config.schema.clone(),
                        revision: config.revision,
                    },
                    arguments.json,
                );
            }
            let report =
                controller::check_from_config(&config).map_err(|error| error.to_string())?;
            // After the controller startup rehearsal, the same synchronous
            // serving composition the daemon runs at startup is validated
            // here; async serving stays the daemon's to prove.
            check_serving_composition(&config, report.authoritative)
                .map_err(|error| error.to_string())?;
            write_report(&report, arguments.json)
        }
        Command::GatewayProjection(arguments) => {
            let config = load_config(&arguments.config_args.config)?;
            gateway_projection_command(&config, &arguments.output)
        }
        // The in-pod verifier boundary never returns through this match:
        // on success the process becomes the launcher, on failure it exits
        // non-zero with the typed reason.
        Command::WorkloadExec(arguments) => {
            super::workload_exec::exec(&super::workload_exec::WorkloadExecInput {
                extension_policy: arguments.extension_policy,
                extension_policy_digest: arguments.extension_policy_digest,
                models_config: arguments.models_config,
                models_config_digest: arguments.models_config_digest,
                agent_dir: arguments.agent_dir,
                state_mount: arguments.state_mount,
                credential_env: arguments.credential_env,
                working_dir: arguments.working_dir,
                trusted_extension: arguments.trusted_extension,
                launcher_argv: arguments.launcher_argv,
            })
        }
        // The passive carrier boundary is the other long-running arm: as the
        // pod's PID1 it returns only under the pod-level stop signal.
        Command::WorkloadPark => super::workload_park::park(),
        Command::BrowserServe(arguments) => {
            super::browser_relay_cli::serve_entry(super::browser_relay_cli::BrowserServeArgs {
                node: arguments.node,
                xvfb: arguments.xvfb,
                screen: arguments.screen,
                state_dir: arguments.state_dir,
                socket: arguments.socket,
            })
        }
        Command::BrowserConnect(arguments) => {
            super::browser_relay_cli::connect_entry(super::browser_relay_cli::BrowserConnectArgs {
                socket: arguments.socket,
                session: arguments.session,
            })
        }
        Command::Huginn(arguments) => {
            let mut config = load_config(&arguments.config_args.config)?;
            // The daemon runs on the projects whose roots exist; one still
            // being provisioned (a failed offline clone) waits for the next
            // start instead of stopping the authority.
            for (project, root) in config.drop_absent_roots() {
                tracing::warn!(
                    "project {project} skipped: its root {} does not exist (yet)",
                    root.display()
                );
            }
            serve_huginn(config)
        }
        Command::Archive(arguments) => crate::archive::run(arguments),
        Command::Delivery(arguments) => crate::delivery::run(arguments),

        Command::OmpConformance(arguments) => omp_conformance::run(
            &arguments.config_args.config,
            &arguments.fixture_root,
            &arguments.output,
        ),
    }
}

fn load_config(path: &Path) -> Result<OdindConfig, String> {
    OdindConfig::load(path).map_err(|error| error.to_string())
}

/// Writes the generated canonical gateway projection to an absent output
/// path and prints the digest to pin as `catalogs.gateway_projection.digest`.
fn gateway_projection_command(config: &OdindConfig, output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err(format!(
            "refusing to clobber existing gateway projection {}",
            output.display()
        ));
    }
    let (bytes, digest) = crate::projection::generate_gateway_projection(config)?;
    std::fs::write(output, &bytes).map_err(|error| {
        format!(
            "could not write gateway projection {}: {error}",
            output.display()
        )
    })?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "gateway projection {} written", output.display())
        .map_err(|error| error.to_string())?;
    writeln!(out, "pin catalogs.gateway_projection.digest = {digest}")
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn write_report(report: &impl Serialize, compact: bool) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if compact {
        serde_json::to_writer(&mut output, report)
    } else {
        serde_json::to_writer_pretty(&mut output, report)
    }
    .map_err(|error| format!("could not serialize report: {error}"))?;
    writeln!(output).map_err(|error| format!("could not write report: {error}"))
}

const CONFIG_CHECK_SCHEMA: &str = "odin.odind-config-check.v1";

/// Report of the `check --config-only` scope: the strict parser and
/// validation accepted the named config.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigCheckReport {
    schema: &'static str,
    config: String,
    config_schema: String,
    revision: u64,
}

#[cfg(test)]
#[path = "tests/entry.rs"]
mod tests;
