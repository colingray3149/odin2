//! The authenticated loopback transport shared by every session surface:
//! endpoint resolution, enrolled device credentials, command identities,
//! typed session commands, the launch-window session lookup, and the
//! explicit terminal-target administration controls.

use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_domain::CommandId;
use odin_huginn::client::{
    RemoteClient, DeviceCredential, EndpointTransport, FileCredentialStore,
};
use odin_huginn::DeviceCredentialStore as _;
use odin_huginn::OdindConfig;
use std::future::Future;
use std::io::Write;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::Duration;

/// The bound of each request to the controller.
pub(super) const LIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Sessions or history events per page of a live-plane walk.
pub(super) const LIVE_PAGE_LIMIT: NonZeroU16 = NonZeroU16::new(128).expect("positive");
/// What exit cleanup (refetch, abort, one epoch retry) may take in all.
pub(super) const CLEANUP_BUDGET: Duration = Duration::from_secs(15);

pub(super) type Client = RemoteClient<EndpointTransport, FileCredentialStore>;

type Connection =
    odin_huginn::client::LiveConnection<odin_huginn::client::EndpointSocket, EndpointTransport>;

pub(crate) struct TerminalRequest {
    pub config: PathBuf,
    pub command: TerminalCommand,
}

/// Target names come from the client; the daemon never reads the client's environment.
pub(crate) enum TerminalCommand {
    Bind(String),
    Unbind,
    Status,
}

pub(crate) fn terminal(request: TerminalRequest, output: &mut dyn Write) -> Result<(), String> {
    let config = OdindConfig::load(&request.config).map_err(|error| {
        format!(
            "could not load the controller configuration {}: {error}",
            request.config.display()
        )
    })?;
    let (client, _credential) = enrolled_client(&config, "terminal target administration")?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start the session client runtime: {error}"))?;
    let live_request = match &request.command {
        TerminalCommand::Bind(name) => {
            validate_terminal_target_name(name)?;
            live::LiveClientRequest::BindTerminalTarget {
                request_id: live_request_id()?,
                zellij_session: name.clone(),
            }
        }
        TerminalCommand::Unbind => live::LiveClientRequest::UnbindTerminalTarget {
            request_id: live_request_id()?,
        },
        TerminalCommand::Status => live::LiveClientRequest::GetTerminalTarget {
            request_id: live_request_id()?,
        },
    };
    let response = runtime.block_on(async {
        let mut connection = client.connect().await.map_err(|error| error.to_string())?;
        tokio::time::timeout(LIVE_REQUEST_TIMEOUT, connection.request_live(live_request))
            .await
            .map_err(|error| format!("the terminal target request timed out: {error}"))?
            .map_err(|error| error.to_string())
    })?;
    let live::LiveResponse::TerminalTarget(status) = response else {
        return Err(format!(
            "the controller answered the terminal target request with {response:?}"
        ));
    };
    let rendered = serde_json::to_string_pretty(&status)
        .map_err(|error| format!("could not serialize the terminal target status: {error}"))?;
    writeln!(output, "{rendered}")
        .map_err(|error| format!("could not write the terminal target status: {error}"))?;
    Ok(())
}

const MAX_TERMINAL_TARGET_NAME_BYTES: usize = 128;

/// Apply the daemon's selector constraints before sending a target name.
fn validate_terminal_target_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > MAX_TERMINAL_TARGET_NAME_BYTES
        || name.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!(
            "terminal target name {name:?} is invalid: names are non-empty, at most \
             {MAX_TERMINAL_TARGET_NAME_BYTES} bytes, with no control characters"
        ));
    }
    Ok(())
}

/// The explicit Zellij session name this interactive client registers as
/// the terminal tab target, read from the CLIENT's own environment. The
/// daemon never reads the environment: only a validated explicit name ever
/// crosses the wire. No variable (or an empty value) means no registration
/// — the daemon's declared selector or unbound state stands.
pub(super) fn zellij_session_name() -> Result<Option<String>, String> {
    match std::env::var("ZELLIJ_SESSION_NAME") {
        Ok(raw) => {
            let name = raw.trim();
            if name.is_empty() {
                return Ok(None);
            }
            validate_terminal_target_name(name)?;
            Ok(Some(name.to_owned()))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(error)) => Err(format!(
            "ZELLIJ_SESSION_NAME is not valid Unicode: {error:?}"
        )),
    }
}

/// This workstation's enrolled device credential; `action` names what needs it.
pub(super) fn enrolled_credential(
    config: &OdindConfig,
    credentials: &FileCredentialStore,
    action: &str,
) -> Result<DeviceCredential, String> {
    credentials
        .load()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "{action} needs an enrolled device credential at {}; pair this loopback \
                 workstation first with `odin huginn --state-root {} devices pair --label \
                 LABEL --node UUID`",
                config
                    .paths
                    .state_root
                    .join("huginn")
                    .join("device.credential")
                    .display(),
                config.paths.state_root.display()
            )
        })
}

/// The authenticated client of the controller's loopback listener, with the credential it
/// uses.
pub(super) fn enrolled_client(
    config: &OdindConfig,
    action: &str,
) -> Result<(Client, DeviceCredential), String> {
    let transport =
        EndpointTransport::new(endpoint_for(config)?).map_err(|error| error.to_string())?;
    let credentials = FileCredentialStore::open(config.paths.state_root.join("huginn"))
        .map_err(|error| error.to_string())?;
    let credential = enrolled_credential(config, &credentials, action)?;
    let client = RemoteClient::with_limits(
        transport,
        credentials,
        odin_huginn::protocol::CodecLimits::default(),
    );
    Ok((client, credential))
}

/// The controller's private listener as a loopback HTTP(S) endpoint.
pub(super) fn endpoint_for(config: &OdindConfig) -> Result<url::Url, String> {
    let scheme = match (
        config.listener.tls_cert.is_some(),
        config.listener.tls_key.is_some(),
    ) {
        (true, true) => "https",
        (false, false) => "http",
        _ => return Err("the controller listener is only half configured for TLS".to_owned()),
    };
    url::Url::parse(&format!("{scheme}://{}", config.listener.address))
        .map_err(|error| format!("invalid controller listener endpoint: {error}"))
}

pub(super) fn generated_command_id() -> Result<CommandId, String> {
    authority_provision::random_command_uuid()
}

/// Sends one existing Huginn session command and returns its durable
/// receipt: `Accepted` is success, and any other receipt is the
/// controller's typed verdict for the caller to interpret (an epoch
/// rejection, for example, is recoverable against the controller's
/// current session fact).
pub(super) fn send_prompt(
    runtime: &tokio::runtime::Runtime,
    client: &RemoteClient<EndpointTransport, FileCredentialStore>,
    command: live::LiveCommand,
) -> Result<live::CommandReceipt, String> {
    runtime.block_on(request_command(client, command))
}

/// One session-command request without entering the runtime. Callers that
/// already hold a `block_on` use this so cleanup cannot nest another.
pub(super) async fn request_command(
    client: &RemoteClient<EndpointTransport, FileCredentialStore>,
    command: live::LiveCommand,
) -> Result<live::CommandReceipt, String> {
    match client
        .request(live::HuginnRequest::SessionCommand(command))
        .await
    {
        Ok(live::HuginnResponse::Command(receipt)) => Ok(receipt),
        Ok(other) => Err(format!(
            "the controller answered the command with {other:?}"
        )),
        Err(error) => Err(error.to_string()),
    }
}

/// One full pagination pass over the live session list.
async fn walk_session_list(
    connection: &mut Connection,
    session_id: live::LiveSessionId,
) -> Result<Option<live::LiveSessionSummary>, String> {
    let mut cursor: Option<live::SessionListCursor> = None;
    loop {
        let response = tokio::time::timeout(
            LIVE_REQUEST_TIMEOUT,
            connection.request_live(live::LiveClientRequest::ListSessions {
                request_id: live_request_id()?,
                seat_id: None,
                include_ended: false,
                cursor,
                limit: LIVE_PAGE_LIMIT,
            }),
        )
        .await
        .map_err(|error| format!("the session list request timed out: {error}"))?
        .map_err(|error| error.to_string())?;
        let live::LiveResponse::Sessions(page) = response else {
            return Err("unexpected session list response".to_owned());
        };
        if let Some(summary) = page
            .sessions
            .into_iter()
            .find(|summary| summary.session_id == session_id)
        {
            return Ok(Some(summary));
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(None),
        }
    }
}

/// One live-list walk, cancellable by the caller's deadline. Absence is not
/// an error: exit cleanup falls back to the threaded operating epoch.
pub(super) async fn lookup_live_session(
    client: &RemoteClient<EndpointTransport, FileCredentialStore>,
    session_id: live::LiveSessionId,
) -> Result<Option<live::LiveSessionSummary>, String> {
    let mut connection = client.connect().await.map_err(|error| error.to_string())?;
    walk_session_list(&mut connection, session_id).await
}

/// Exit Abort for the current epoch: one list refetch, one send, and one
/// `EpochMismatch` retry. The caller bounds the whole future. A failed or
/// absent refetch keeps `epoch` (the chat loop's operating epoch), never an
/// attach-time snapshot stored elsewhere.
pub(super) async fn abort_current_epoch(
    client: &RemoteClient<EndpointTransport, FileCredentialStore>,
    session_id: live::LiveSessionId,
    epoch: &mut live::SessionEpoch,
    state: &mut live::LiveSessionState,
    output: &mut dyn Write,
) -> Result<(), String> {
    if let Ok(Some(found)) = lookup_live_session(client, session_id).await {
        *epoch = found.epoch;
        *state = found.state;
    }
    let receipt = request_command(
        client,
        live::LiveCommand {
            command_id: generated_command_id()?,
            session_id,
            expected_epoch: *epoch,
            expected_event_head: None,
            body: live::LiveCommandBody::Abort {
                scope: live::AbortScope::Session,
            },
        },
    )
    .await?;
    let receipt = match receipt {
        live::CommandReceipt::Accepted { .. } => return Ok(()),
        live::CommandReceipt::Rejected {
            reason: live::CommandRejection::EpochMismatch { .. },
            ..
        } => {
            let refreshed = lookup_live_session(client, session_id)
                .await?
                .ok_or_else(|| format!("session {session_id} is not live on the controller"))?;
            writeln!(
                output,
                "\n[epoch {} → {}] the controller reclaimed this session while it was \
                 attached; recovered the current session fact and resending",
                epoch.get(),
                refreshed.epoch.get()
            )
            .map_err(|error| error.to_string())?;
            *epoch = refreshed.epoch;
            *state = refreshed.state;
            request_command(
                client,
                live::LiveCommand {
                    command_id: generated_command_id()?,
                    session_id,
                    expected_epoch: *epoch,
                    expected_event_head: None,
                    body: live::LiveCommandBody::Abort {
                        scope: live::AbortScope::Session,
                    },
                },
            )
            .await?
        }
        other => {
            return Err(format!(
                "the controller did not accept the command: {other:?}"
            ))
        }
    };
    match receipt {
        live::CommandReceipt::Accepted { .. } => Ok(()),
        other => Err(format!(
            "the controller did not accept the command: {other:?}"
        )),
    }
}

/// One fresh live-plane request correlation id.
pub(super) fn live_request_id() -> Result<live::RequestId, String> {
    live::RequestId::parse(&generated_command_id()?.to_string()).map_err(|error| error.to_string())
}

/// How long attach keeps looking for a session whose tab opened before its actor registered.
const ATTACH_LAUNCH_WINDOW: Duration = Duration::from_secs(10);
const ATTACH_LAUNCH_POLL: Duration = Duration::from_millis(250);

/// Repeats one bounded `walk` (a full pagination pass over the live session
/// list) until it yields the session or the launch window closes. Only
/// absence is retried: a walk error — transport failure, timeout, malformed
/// response — aborts immediately so real faults never hide behind retries.
async fn retry_through_launch_window<T, W, F>(
    mut walk: W,
    window: Duration,
    poll: Duration,
) -> Result<Option<T>, String>
where
    W: FnMut() -> F,
    F: Future<Output = Result<Option<T>, String>>,
{
    let started = tokio::time::Instant::now();
    loop {
        if let Some(found) = walk().await? {
            return Ok(Some(found));
        }
        if started.elapsed() >= window {
            return Ok(None);
        }
        tokio::time::sleep(poll).await;
    }
}

/// Locates one live session by identity through the controller's real
/// session list. Ended and failed sessions are excluded by the query:
/// attaching requires a live conversation partner. A session's tab is
/// created during the session's own launch, so the tab's attach client can
/// finish its first walk before the supervisor registers the new actor: the
/// lookup keeps walking through a bounded launch window instead of failing
/// on that race, while genuine absence after the window keeps the typed
/// not-live refusal.
pub(super) fn find_live_session(
    runtime: &tokio::runtime::Runtime,
    client: &RemoteClient<EndpointTransport, FileCredentialStore>,
    session_id: live::LiveSessionId,
) -> Result<live::LiveSessionSummary, String> {
    runtime.block_on(async {
        let shared = std::sync::Arc::new(tokio::sync::Mutex::new(
            client.connect().await.map_err(|error| error.to_string())?,
        ));
        retry_through_launch_window(
            move || {
                let shared = std::sync::Arc::clone(&shared);
                async move { walk_session_list(&mut *shared.lock().await, session_id).await }
            },
            ATTACH_LAUNCH_WINDOW,
            ATTACH_LAUNCH_POLL,
        )
        .await?
        .ok_or_else(|| {
            format!(
                "session {session_id} is not live on the controller; attach requires \
                 an existing live session (`odin huginn ... sessions` lists them)"
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_lookup_retries_through_the_launch_window_race() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let walks = std::sync::atomic::AtomicU8::new(0);
        let found = runtime
            .block_on(retry_through_launch_window::<u32, _, _>(
                || async {
                    if walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                        // The tab pane's first walks race the actor spawn:
                        // the session is not in the list yet.
                        Ok(None)
                    } else {
                        Ok(Some(7))
                    }
                },
                Duration::from_secs(10),
                Duration::from_millis(1),
            ))
            .unwrap();
        assert_eq!(found, Some(7), "the third walk finds the session");
        assert_eq!(
            walks.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "exactly one walk per poll, no extra walk after success"
        );
    }

    #[test]
    fn attach_lookup_never_retries_a_walk_error() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let walks = std::sync::atomic::AtomicU8::new(0);
        let error = runtime
            .block_on(retry_through_launch_window::<u32, _, _>(
                || async {
                    walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err("transport refused".to_owned())
                },
                Duration::from_secs(10),
                Duration::from_millis(1),
            ))
            .unwrap_err();
        assert_eq!(error, "transport refused");
        assert_eq!(
            walks.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "real faults abort immediately"
        );
    }
}
