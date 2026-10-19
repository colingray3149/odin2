use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::session;

#[derive(Debug, Args)]
#[command(subcommand_negates_reqs = true)]
pub(crate) struct SessionArgs {
    /// Controller configuration: the explicit `--config` path wins over the
    /// wrapper-provided `ODIN_CONFIG` environment default; with neither, the
    /// invocation fails with a typed error naming both.
    #[arg(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,

    /// Seat to open; defaults to the declared chat seat
    /// (`[hermes.discord].seat`) when omitted.
    #[arg(long, value_name = "ID")]
    pub(crate) seat: Option<String>,
    /// Project to open; defaults to the exact declared transport project
    /// (`[hermes.discord].project`) for the transport seat only. A seat that
    /// differs from the transport seat must name its project explicitly —
    /// no default is ever inferred from lane order.
    #[arg(long, value_name = "ID")]
    pub(crate) project: Option<String>,
    /// Declared launch provider to open with; required unless `--attach`.
    #[arg(long, value_name = "PROVIDER", required_unless_present = "attach")]
    pub(crate) provider: Option<String>,
    /// Declared launch model to open with; required unless `--attach`.
    #[arg(long, value_name = "MODEL", required_unless_present = "attach")]
    pub(crate) model: Option<String>,
    /// Stable operator command identity. Generated when omitted.
    #[arg(long, value_name = "UUID")]
    pub(crate) command_id: Option<String>,
    /// Optional first prompt; read once, persisted as the session's private
    /// plan objective, accepted, and only then sent after the idle open.
    #[arg(long, value_name = "PATH")]
    pub(crate) prompt_file: Option<PathBuf>,
    /// Run the governed OMP session in this terminal; closing it stops its workers.
    #[arg(long, conflicts_with = "json")]
    pub(crate) interactive: bool,
    /// Ask the production supervisor not to open its persistent zellij tab.
    #[arg(long)]
    pub(crate) headless: bool,
    /// Emit one machine-readable open report.
    #[arg(long)]
    pub(crate) json: bool,
    /// Attach the interactive client to an EXISTING live session. No new
    /// session is opened and quitting DETACHES — the session keeps running.
    #[arg(
        long,
        value_name = "UUID",
        conflicts_with_all = [
            "json",
            "prompt_file",
            "headless",
            "seat",
            "project",
            "provider",
            "model",
            "command_id"
        ]
    )]
    pub(crate) attach: Option<String>,
    /// Explicit operator terminal-target administration.
    #[command(subcommand)]
    pub(crate) terminal: Option<TerminalCommand>,
}

impl SessionArgs {
    pub(crate) fn into_invocation(self) -> Result<SessionInvocation, String> {
        if let Some(terminal) = self.terminal {
            return Ok(SessionInvocation::Terminal(match terminal {
                TerminalCommand::Bind {
                    config,
                    zellij_session,
                } => session::TerminalRequest {
                    config: resolve_config(config.as_ref())?,
                    command: session::TerminalCommand::Bind(zellij_session),
                },
                TerminalCommand::Unbind { config } => session::TerminalRequest {
                    config: resolve_config(config.as_ref())?,
                    command: session::TerminalCommand::Unbind,
                },
                TerminalCommand::Status { config } => session::TerminalRequest {
                    config: resolve_config(config.as_ref())?,
                    command: session::TerminalCommand::Status,
                },
            }));
        }
        Ok(SessionInvocation::Open(session::SessionRequest {
            config: resolve_config(self.config.as_ref())?,
            seat: self.seat,
            project: self.project,
            provider: self.provider,
            model: self.model,
            command_id: self.command_id,
            prompt_file: self.prompt_file,
            headless: self.headless || self.interactive,
            interactive: self.interactive || self.attach.is_some(),
            json: self.json,
            attach: self.attach,
        }))
    }
}

/// Resolves the controller configuration for one `odin session` invocation:
/// the explicit `--config` flag wins over the wrapper-provided `ODIN_CONFIG`
/// environment default, and with neither the typed error names both — no
/// default path is ever guessed or discovered.
fn resolve_config(explicit: Option<&PathBuf>) -> Result<PathBuf, String> {
    if let Some(config) = explicit {
        return Ok(config.clone());
    }
    match std::env::var("ODIN_CONFIG") {
        Ok(value) if !value.trim().is_empty() => Ok(PathBuf::from(value)),
        Ok(_) | Err(std::env::VarError::NotPresent) => Err(
            "no controller configuration was declared: pass --config <PATH> or set ODIN_CONFIG=<PATH>"
                .to_owned(),
        ),
        Err(error) => Err(format!(
            "could not read the ODIN_CONFIG environment default: {error}"
        )),
    }
}

/// One resolved `odin session` invocation: the open/attach surface or the
/// explicit terminal-target administration surface.
pub(crate) enum SessionInvocation {
    Open(session::SessionRequest),
    Terminal(session::TerminalRequest),
}

#[derive(Debug, Subcommand)]
pub(crate) enum TerminalCommand {
    /// Register this Zellij session as the terminal tab target. The name is
    /// sent explicitly; the daemon never reads the client environment.
    Bind {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[arg(value_name = "NAME")]
        zellij_session: String,
    },
    /// Clear an explicitly registered target (falls back to the declared
    /// selector or unbound).
    Unbind {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Show the current terminal tab target status.
    Status {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub(crate) struct PlanArgs {
    #[arg(long, value_name = "PATH")]
    pub(crate) config: PathBuf,
    #[command(subcommand)]
    command: PlanCommand,
}

impl PlanArgs {
    pub(crate) fn into_accept_request(self) -> session::PlanAcceptRequest {
        let PlanArgs { config, command } = self;
        match command {
            PlanCommand::Accept(arguments) => session::PlanAcceptRequest {
                config,
                session: arguments.session,
                expected_revision: arguments.expected_revision,
            },
        }
    }
}

#[derive(Debug, Subcommand)]
enum PlanCommand {
    /// Record real operator acceptance of the exact current plan of one
    /// local session run, bound to the paired operator device identity.
    Accept(PlanAcceptArgs),
}

#[derive(Debug, Args)]
struct PlanAcceptArgs {
    /// The live session whose bridge run plan is accepted.
    #[arg(long, value_name = "UUID")]
    session: String,
    /// The exact plan revision to accept; defaults to the current revision.
    #[arg(long, value_name = "REVISION")]
    expected_revision: Option<i64>,
}
