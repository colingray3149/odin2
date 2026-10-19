use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use odin_cli::authority_provision;
use odin_huginn::OdindConfig;

use crate::RunStatus;

#[derive(Debug, Args)]
pub(crate) struct AuthorityArgs {
    #[command(subcommand)]
    pub(crate) command: AuthorityCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthorityCommand {
    /// Create or validate the configured private key and token roots.
    Init(AuthorityInitArgs),
    /// Mint one bounded token for an exact supervisor command identity.
    Mint(AuthorityMintArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AuthorityInitArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct AuthorityMintArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "UUID")]
    command_id: String,
    #[arg(long, value_name = "ID")]
    seat: String,
    #[arg(long, value_name = "ID")]
    project: String,
    /// Declared launch provider this authority is minted for; proven a
    /// declared option of the seat before any token is written.
    #[arg(long, value_name = "PROVIDER")]
    provider: String,
    /// Declared launch model this authority is minted for; proven a declared
    /// option of the seat before any token is written.
    #[arg(long, value_name = "MODEL")]
    model: String,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = authority_provision::DEFAULT_TOKEN_TTL_SECONDS
    )]
    pub(crate) ttl_seconds: u64,
    /// Explicitly replace the existing same-session token.
    #[arg(long)]
    pub(crate) renew: bool,
}

pub(crate) fn authority_command(
    arguments: AuthorityArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    match arguments.command {
        AuthorityCommand::Init(arguments) => {
            let config = OdindConfig::load(&arguments.config).map_err(|error| {
                format!(
                    "could not load the controller configuration {}: {error}",
                    arguments.config.display()
                )
            })?;
            let report = authority_provision::init(&config)?;
            writeln!(
                output,
                "runtime state root: {} ({}; mode 0700)",
                report.state_root.display(),
                if report.state_root_created {
                    "created"
                } else {
                    "validated"
                }
            )
            .map_err(|error| format!("could not write authority report: {error}"))?;
            writeln!(
                output,
                "authority token root: {} ({}; mode 0700)",
                report.token_root.display(),
                if report.token_root_created {
                    "created"
                } else {
                    "validated"
                }
            )
            .map_err(|error| format!("could not write authority report: {error}"))?;
            writeln!(
                output,
                "verification key: {} ({}; {} bytes; mode 0600)",
                report.verification_key_file.display(),
                if report.key_created {
                    "created"
                } else {
                    "preserved"
                },
                report.key_bytes
            )
            .map_err(|error| format!("could not write authority report: {error}"))?;
        }
        AuthorityCommand::Mint(arguments) => {
            let config = OdindConfig::load(&arguments.config).map_err(|error| {
                format!(
                    "could not load the controller configuration {}: {error}",
                    arguments.config.display()
                )
            })?;
            let command_id = authority_provision::parse_command_uuid(&arguments.command_id)?;
            let report = authority_provision::mint(
                &config,
                &arguments.seat,
                &arguments.project,
                &command_id,
                authority_provision::LaunchSelection::new(&arguments.provider, &arguments.model),
                arguments.ttl_seconds,
                arguments.renew,
            )?;
            writeln!(output, "session: {}", report.session)
                .and_then(|_| writeln!(output, "token id: {}", report.token_id))
                .and_then(|_| {
                    writeln!(
                        output,
                        "claims: seat={} slice={} lane={}",
                        report.seat, report.slice, report.lane
                    )
                })
                .and_then(|_| writeln!(output, "lifetime: {} seconds", report.ttl_seconds))
                .and_then(|_| {
                    writeln!(
                        output,
                        "token file: {} ({})",
                        report.token_path.display(),
                        if report.renewed { "renewed" } else { "created" }
                    )
                })
                .map_err(|error| format!("could not write authority report: {error}"))?;
        }
    }
    Ok(RunStatus::Success)
}
