//! The `browser` command domain: browser snapshots, bounded watches, and
//! typed takeover, release, and command dispatch.

use clap::{Args, Subcommand};
use odin_domain::huginn as live;

use super::surface::{
    parse_protocol_json, snapshot_plan, watch_plan_for, HuginnPageArgs, HuginnPlan,
    HuginnProtocolJsonArgs, HuginnWatchArgs,
};

#[derive(Debug, Args)]
pub(crate) struct HuginnBrowserArgs {
    #[command(subcommand)]
    pub(super) command: HuginnBrowserCommand,
}

#[derive(Debug, Subcommand)]
pub(super) enum HuginnBrowserCommand {
    List(HuginnPageArgs),
    Watch(HuginnWatchArgs),
    Takeover(HuginnTakeoverArgs),
    Release(HuginnTakeoverArgs),
    Command(HuginnProtocolJsonArgs),
}

/// A takeover or hand-back: either the exact typed command JSON, or the
/// session, this device and the session's control revision, from which the
/// CLI composes the typed command and its arguments digest.
#[derive(Debug, Args)]
pub(super) struct HuginnTakeoverArgs {
    /// Exact JSON encoding of the typed takeover command.
    #[arg(long, value_name = "JSON", conflicts_with_all = ["session", "device", "revision"])]
    request_json: Option<String>,
    /// The browser session to take over or hand back.
    #[arg(long, value_name = "UUID", requires_all = ["device", "revision"])]
    session: Option<String>,
    /// This paired device's id (`odin huginn devices list`).
    #[arg(long, value_name = "UUID")]
    device: Option<String>,
    /// The session's current control revision.
    #[arg(long, value_name = "N")]
    revision: Option<u64>,
}

impl HuginnBrowserCommand {
    pub(super) fn into_plan(self) -> Result<HuginnPlan, String> {
        match self {
            Self::List(page) => Ok(snapshot_plan(live::ObjectKind::Browser, page)),
            Self::Watch(arguments) => watch_plan_for(
                arguments,
                live::LiveStreamKind::BrowserFrames,
                "browser watch",
            ),
            Self::Takeover(arguments) => takeover_plan(arguments, true),
            Self::Release(arguments) => takeover_plan(arguments, false),
            Self::Command(arguments) => browser_command_plan(arguments, None),
        }
    }
}

fn takeover_plan(arguments: HuginnTakeoverArgs, acquire: bool) -> Result<HuginnPlan, String> {
    match (
        arguments.request_json,
        arguments.session,
        arguments.device,
        arguments.revision,
    ) {
        (Some(request_json), None, None, None) => {
            browser_command_plan(HuginnProtocolJsonArgs { request_json }, Some(acquire))
        }
        (None, Some(session), Some(device), Some(revision)) => {
            Ok(HuginnPlan::request(live::HuginnRequest::BrowserCommand(
                takeover_command(&session, &device, revision, acquire)?,
            )))
        }
        _ => Err(
            "browser takeover/release needs --request-json, or --session, --device and \
                  --revision"
                .to_owned(),
        ),
    }
}

/// The typed takeover command with the arguments digest the authority
/// verifies: blake3 over the JSON of (command, session, revision).
fn takeover_command(
    session: &str,
    device: &str,
    revision: u64,
    acquire: bool,
) -> Result<live::BrowserCommand, String> {
    let session_id =
        live::BrowserSessionId::parse(session).map_err(|error| format!("--session: {error}"))?;
    let device_id = live::DeviceId::parse(device).map_err(|error| format!("--device: {error}"))?;
    let command = if acquire {
        live::BrowserTakeoverCommand::Acquire { device_id }
    } else {
        live::BrowserTakeoverCommand::Release { device_id }
    };
    let bound = serde_json::to_value((&command, session_id, revision))
        .and_then(|value| serde_json::to_vec(&value))
        .map_err(|error| format!("takeover arguments: {error}"))?;
    let command_id = odin_domain::CommandId::new(format!("cli:takeover:{}", uuid::Uuid::new_v4()))
        .map_err(|error| error.to_string())?;
    Ok(live::BrowserCommand::Takeover {
        context: live::BrowserCommandContext {
            command_id,
            session_id,
            expected_revision: revision,
            arguments_digest: odin_domain::Digest::hash(&bound),
            approval_id: None,
        },
        command,
    })
}

fn browser_command_plan(
    arguments: HuginnProtocolJsonArgs,
    takeover: Option<bool>,
) -> Result<HuginnPlan, String> {
    let command: live::BrowserCommand =
        parse_protocol_json(&arguments.request_json, "browser command")?;
    if let Some(acquire) = takeover {
        let valid = matches!(
            &command,
            live::BrowserCommand::Takeover {
                command: live::BrowserTakeoverCommand::Acquire { .. },
                ..
            } if acquire
        ) || matches!(
            &command,
            live::BrowserCommand::Takeover {
                command: live::BrowserTakeoverCommand::Release { .. },
                ..
            } if !acquire
        );
        if !valid {
            return Err(
                "browser takeover/release requires the matching typed takeover command".to_owned(),
            );
        }
    }
    Ok(HuginnPlan::request(live::HuginnRequest::BrowserCommand(
        command,
    )))
}

#[cfg(test)]
mod takeover_tests {
    use super::takeover_command;

    #[test]
    fn a_takeover_from_flags_carries_the_digest_the_authority_accepted() {
        let command = takeover_command(
            "66259c26-08d6-47fc-967d-020b704be60d",
            "a681066c-df4f-4615-81a8-76cccbddb8a3",
            345,
            true,
        )
        .expect("takeover composes");
        assert_eq!(
            command.context().arguments_digest.to_string(),
            "blake3:df3d844ebf6f6322371f96394f7b0cd5e07b6a948464f3f1d2db23af5a356014"
        );
        assert!(takeover_command(
            "not-a-uuid",
            "a681066c-df4f-4615-81a8-76cccbddb8a3",
            1,
            false
        )
        .is_err());
    }
}
