#![forbid(unsafe_code)]
#![deny(dead_code)]

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod commands;
mod session;
#[cfg(test)]
mod test_support;

use commands::approval::{decide, print_seat_menu, ApproveArgs, RejectArgs};
use commands::atlas::{providers, ProvidersArgs};
use commands::authority::{authority_command, AuthorityArgs};
use commands::compute_sample::{compute_sample, ComputeSampleArgs};
use commands::context::{context, ContextArgs};
use commands::huginn::{run_huginn, HuginnArgs};
use commands::models::{models_command, ModelsArgs};
use commands::registry::{author_command, registry_command, AuthorArgs, RegistryArgs};
use commands::resolve_odin_root;
use commands::session::{PlanArgs, SessionArgs, SessionInvocation};
use commands::worker::{emergency_stop, EmergencyStopArgs};
use odin_cli::feature_probe::{feature_probe, FeatureProbeArgs};
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use odin_kernel::ApprovalDecision;

#[derive(Debug, Parser)]
#[command(name = "odin", version, about = "Odin's command line")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Approve a pending approval request.
    Approve(ApproveArgs),
    /// Reject a pending approval request.
    Reject(RejectArgs),
    /// Stop the workers a stop file names (or every running one), with no
    /// model or network involved.
    EmergencyStop(EmergencyStopArgs),
    /// Show each model lane's provider, lease and quota (never credentials).
    Providers(ProvidersArgs),
    /// Every model plan and key, its window use, and the classes in order
    /// (`odin huginn models`); `refresh`, `card` and `render` manage the
    /// AVAILABLE catalog, model cards and the live gateway.
    #[command(alias = "quota")]
    Models(ModelsArgs),
    /// Publish the committed registry.
    Registry(RegistryArgs),
    /// Check registry edits and stage them for review.
    Author(AuthorArgs),
    /// Set up the signing keys and mint launch tokens.
    Authority(AuthorityArgs),
    /// Talk to the running daemon: chat, sessions, terminals, files, workloads.
    Huginn(HuginnArgs),
    /// Open a session for a declared seat and project.
    Session(SessionArgs),
    /// Accept the current plan of a local session run.
    Plan(PlanArgs),
    /// What each injection put into a session's context (its blocks, tokens, sources).
    Context(ContextArgs),
    /// Every active seat live, and one input line to Sinmara (`/model` changes her model).
    View(commands::view::ViewArgs),
    /// List, search or read one declared file root on this host (run by the
    /// authority over SSH for a seat's file share).
    #[command(hide = true)]
    HostFile(commands::host_file::HostFileArgs),
    /// One finite compute sample for this host, then exit. The authority
    /// runs this over SSH; it is not an operator command.
    #[command(hide = true)]
    ComputeSample(ComputeSampleArgs),
    /// Evaluate this host's `unit:` and `file:` feature checks once, then exit. JSON to stdout.
    FeatureProbe(FeatureProbeArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunStatus {
    Success,
    Redirect,
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
    let cli = Cli::parse();
    // The view writes stdout from several threads, so it never runs under
    // the one lock every other command holds.
    let result = match cli.command {
        Some(Command::View(arguments)) => {
            commands::view::run(arguments).map(|()| RunStatus::Success)
        }
        command => run(Cli { command }, &mut io::stdout().lock()),
    };
    match result {
        Ok(RunStatus::Success) => ExitCode::SUCCESS,
        Ok(RunStatus::Redirect) => ExitCode::FAILURE,
        Err(error) => {
            // A closed stderr must not turn an error exit into a panic.
            let _ = writeln!(io::stderr(), "odin: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli, output: &mut impl Write) -> Result<RunStatus, String> {
    match cli.command {
        None => {
            print_seat_menu(output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::Approve(arguments)) => decide(
            arguments.target,
            ApprovalDecision::Approve {
                evidence_ref: arguments.evidence,
            },
            output,
        ),
        Some(Command::Reject(arguments)) => {
            let evidence_ref = arguments
                .evidence
                .unwrap_or_else(|| format!("rejected by {}", arguments.target.decider));
            decide(
                arguments.target,
                ApprovalDecision::Deny { evidence_ref },
                output,
            )
        }
        Some(Command::EmergencyStop(arguments)) => {
            emergency_stop(arguments)?;
            Ok(RunStatus::Success)
        }
        Some(Command::Providers(arguments)) => {
            let registry_root = resolve_odin_root()?.join("registry");
            providers(arguments, &registry_root, output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::Registry(arguments)) => registry_command(arguments, output),
        Some(Command::Author(arguments)) => author_command(arguments, output),
        Some(Command::Authority(arguments)) => authority_command(arguments, output),
        Some(Command::Huginn(arguments)) => {
            run_huginn(arguments, output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::Models(arguments)) => match arguments.command {
            None => {
                // The same request as `odin huginn models`, with its endpoint and state defaults.
                let argv = ["odin", "huginn", "models"]
                    .into_iter()
                    .chain(arguments.json.then_some("--json"));
                let Some(Command::Huginn(arguments)) = Cli::try_parse_from(argv)
                    .map_err(|error| error.to_string())?
                    .command
                else {
                    return Err("odin models: `odin huginn models` did not parse".to_owned());
                };
                run_huginn(arguments, output)?;
                Ok(RunStatus::Success)
            }
            Some(command) => models_command(command, output),
        },
        Some(Command::HostFile(arguments)) => {
            commands::host_file::host_file(arguments, output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::ComputeSample(arguments)) => {
            compute_sample(arguments, output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::FeatureProbe(arguments)) => {
            feature_probe(arguments, output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::View(_)) => Err("odin view runs outside the shared stdout lock".to_owned()),
        Some(Command::Session(arguments)) => {
            match arguments.into_invocation()? {
                SessionInvocation::Open(request) => session::start(request, output)?,
                SessionInvocation::Terminal(request) => session::terminal(request, output)?,
            }
            Ok(RunStatus::Success)
        }
        Some(Command::Plan(arguments)) => {
            session::accept(arguments.into_accept_request(), output)?;
            Ok(RunStatus::Success)
        }
        Some(Command::Context(arguments)) => {
            context(arguments, output)?;
            Ok(RunStatus::Success)
        }
    }
}
