#![forbid(unsafe_code)]
#![deny(dead_code)]

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod commands;
mod session;

use commands::account::{account_command, AccountArgs};
use commands::approval::{decide, print_seat_menu, ApproveArgs, RejectArgs};
use commands::atlas::{providers, ProvidersArgs};
use commands::authority::{authority_command, AuthorityArgs};
use commands::huginn::{run_huginn, HuginnArgs};
use commands::registry::{author_command, registry_command, AuthorArgs, RegistryArgs};
use commands::resolve_odin_root;
use commands::session::{PlanArgs, SessionArgs, SessionInvocation};
use commands::worker::{emergency_stop, EmergencyStopArgs};
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use odin_kernel::ApprovalDecision;

#[derive(Debug, Parser)]
#[command(name = "odin", version, about = "Odin operator interface")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bind life provider accounts through one-time OAuth consent.
    Account(AccountArgs),
    /// Approve a pending exact-revision approval request.
    Approve(ApproveArgs),
    /// Reject a pending exact-revision approval request.
    Reject(RejectArgs),
    /// Stop every durably registered worker in a private fixture without
    /// model or network access.
    EmergencyStop(EmergencyStopArgs),
    /// Show the validated provider authority plus per-lane lease status,
    /// lineage, and quota from a state root, without credentials.
    Providers(ProvidersArgs),
    /// Publish one committed registry snapshot.
    Registry(RegistryArgs),
    /// Compile, validate, and stage committed typed authoring fills.
    Author(AuthorArgs),
    /// Provision and mint the private runtime authority.
    Authority(AuthorityArgs),
    /// Operate the complete private Huginn/ColinRemote protocol surface.
    Huginn(HuginnArgs),
    /// Provision authority and open a declared seat/project session through
    /// the existing production Huginn supervisor.
    Session(SessionArgs),
    /// Durable operator plan acceptance for local session runs.
    Plan(PlanArgs),
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
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match run(cli, &mut output) {
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
        Some(Command::Account(arguments)) => account_command(arguments, output),
        Some(Command::Approve(arguments)) => decide(
            arguments.target,
            ApprovalDecision::Approve {
                evidence_ref: arguments.evidence,
            },
            output,
        ),
        Some(Command::Reject(arguments)) => {
            if arguments.evidence.trim().is_empty() {
                return Err("rejection evidence must not be empty".to_owned());
            }
            decide(
                arguments.target,
                ApprovalDecision::Deny {
                    evidence_ref: arguments.evidence,
                },
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
    }
}
