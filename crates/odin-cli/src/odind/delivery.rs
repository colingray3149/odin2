//! Inspect and reconcile confirmed deliveries locally; never dispatch a reply.

use std::io::Write;
use std::path::{Path, PathBuf};

use odin_domain::huginn::OpaqueCredentialHandle;
use odin_hermes::conversation::delivery;
use odin_hermes::discord::{DiscordCredential, DiscordRestTransport, SecretToken};
use odin_huginn::OdindConfig;

#[derive(Debug, clap::Args)]
pub(crate) struct DeliveryArgs {
    #[command(subcommand)]
    command: DeliveryCommand,
}

#[derive(Debug, clap::Subcommand)]
enum DeliveryCommand {
    /// List durable delivery metadata without reply bodies or credentials.
    Inspect(ConfigArgs),
    /// Adopt one confirmed applied operation after its old dispatcher has exited.
    /// Does not resend, reset, or accept uncertainty as evidence.
    Reconcile(ReconcileArgs),
}

#[derive(Debug, clap::Args)]
struct ConfigArgs {
    /// Strict generated odind.toml; uses its existing state_root/ledger.sqlite3.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, clap::Args)]
struct ReconcileArgs {
    #[command(flatten)]
    config_args: ConfigArgs,
    /// Exact durable delivery ID from inspect.
    #[arg(long, value_name = "ID", value_parser = nonblank)]
    delivery_id: String,
    /// Exact observed ledger revision (stale observations are rejected).
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    expected_revision: i64,
    /// Exact pending physical operation sequence from inspect.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    sequence: u64,
    /// Exact Discord message ID, including the target of a pending DELETE.
    #[arg(long, value_name = "ID", value_parser = nonblank)]
    message_id: String,
}

fn nonblank(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("must not be blank".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn existing_ledger(state_root: &Path) -> Result<PathBuf, String> {
    let path = state_root.join("ledger.sqlite3");
    if !path.is_file() {
        return Err(format!(
            "configured delivery ledger {} is not an existing file; refusing to create a database",
            path.display()
        ));
    }
    Ok(path)
}

fn transport(config: &OdindConfig) -> Result<DiscordRestTransport, String> {
    let section = config.hermes.as_ref().ok_or("Hermes is not configured")?;
    let settings = crate::hermes::hermes_settings(section)?;
    let discord = settings
        .discord
        .as_ref()
        .ok_or("Hermes Discord is not configured")?;
    // Use HermesRuntime's configured credential source and endpoint, not operator overrides.
    let token = std::env::var(odin_hermes::runtime::DISCORD_TOKEN_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("DISCORD_BOT_TOKEN is required for exact delivery reconciliation")?;
    let handle = OpaqueCredentialHandle::new(discord.bot_token_handle.clone())
        .map_err(|error| error.to_string())?;
    let secret = SecretToken::new(token).map_err(|error| error.to_string())?;
    Ok(DiscordRestTransport::new(DiscordCredential::token(
        handle, secret,
    )))
}

pub(crate) fn run(args: DeliveryArgs) -> Result<(), String> {
    let config_path = match &args.command {
        DeliveryCommand::Inspect(arguments) => &arguments.config,
        DeliveryCommand::Reconcile(arguments) => &arguments.config_args.config,
    };
    let config = OdindConfig::load(config_path).map_err(|error| error.to_string())?;
    let ledger_path = existing_ledger(&config.paths.state_root)?;
    let report = match args.command {
        DeliveryCommand::Inspect(_) => delivery::inspect(&ledger_path)?,
        DeliveryCommand::Reconcile(arguments) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async {
                let transport = transport(&config)?;
                delivery::reconcile(
                    &ledger_path,
                    &arguments.delivery_id,
                    arguments.expected_revision,
                    arguments.sequence,
                    Some(&arguments.message_id),
                    &transport,
                )
                .await
            })?
        }
    };
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &report).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        delivery: DeliveryArgs,
    }

    fn reconcile_arguments() -> Vec<&'static str> {
        vec![
            "delivery",
            "reconcile",
            "--config",
            "odind.toml",
            "--delivery-id",
            "reply:one",
            "--expected-revision",
            "7",
            "--sequence",
            "3",
            "--message-id",
            "123",
        ]
    }

    #[test]
    fn reconcile_preserves_exact_evidence_arguments() {
        let parsed = TestCli::try_parse_from(reconcile_arguments()).expect("reconcile arguments");
        let DeliveryCommand::Reconcile(arguments) = parsed.delivery.command else {
            panic!("expected reconcile");
        };
        assert_eq!(arguments.delivery_id, "reply:one");
        assert_eq!(arguments.expected_revision, 7);
        assert_eq!(arguments.sequence, 3);
        assert_eq!(arguments.message_id, "123");
    }

    #[test]
    fn reconcile_requires_explicit_identity_and_positive_fences() {
        let mut missing_message = reconcile_arguments();
        missing_message.truncate(10);
        assert!(TestCli::try_parse_from(missing_message).is_err());
        for (index, value) in [(5, " "), (7, "0"), (7, "-1"), (9, "0"), (11, " ")] {
            let mut arguments = reconcile_arguments();
            arguments[index] = value;
            assert!(TestCli::try_parse_from(arguments).is_err());
        }
        for forbidden in ["--retry", "--reset", "--accept-risk", "--force"] {
            let mut arguments = reconcile_arguments();
            arguments.push(forbidden);
            assert!(TestCli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn missing_ledger_is_not_created() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let root = directory.path().join("missing-state");
        let error = existing_ledger(&root).expect_err("missing ledger rejected");
        assert!(error.contains("refusing to create a database"));
        assert!(!root.exists());
        std::fs::create_dir(&root).expect("state directory");
        std::fs::create_dir(root.join("ledger.sqlite3")).expect("non-file ledger");
        assert!(existing_ledger(&root).is_err());
    }

    #[test]
    fn inspect_loads_strict_config_and_refuses_absent_configured_ledger() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let path = directory.path().join("odind.toml");
        std::fs::write(
            &path,
            crate::test_fixture::fixture_config_text(
                directory.path(),
                &directory.path().join("snapshot.json"),
            ),
        )
        .expect("fixture config");
        let error = run(DeliveryArgs {
            command: DeliveryCommand::Inspect(ConfigArgs {
                config: path.clone(),
            }),
        })
        .expect_err("no configured ledger");
        assert!(error.contains("refusing to create a database"));
        std::fs::write(&path, "unknown = true").expect("invalid config");
        let error = run(DeliveryArgs {
            command: DeliveryCommand::Inspect(ConfigArgs { config: path }),
        })
        .expect_err("strict config rejects unknown input");
        assert!(!error.contains("refusing to create a database"));
    }
}
