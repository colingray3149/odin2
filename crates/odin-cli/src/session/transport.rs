//! The authenticated loopback transport shared by every session surface:
//! endpoint resolution, enrolled device credentials, command identities,
//! typed session commands, the launch-window session lookup, and the
//! explicit terminal-target administration controls.

use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_domain::CommandId;
use odin_huginn::client::{ColinRemoteClient, EndpointTransport, FileCredentialStore};
use odin_huginn::DeviceCredentialStore as _;
use odin_huginn::OdindConfig;
use std::future::Future;
use std::io::Write;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
    let endpoint = endpoint_for(&config)?;
    let limits = odin_huginn::protocol::CodecLimits::default();
    let transport = EndpointTransport::new(endpoint).map_err(|error| error.to_string())?;
    let credential_root = config.paths.state_root.join("huginn");
    let credentials =
        FileCredentialStore::open(&credential_root).map_err(|error| error.to_string())?;
    credentials
        .load()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "terminal target administration requires an enrolled device credential at \
                 {}; pair this loopback workstation first with `odin huginn --state-root {} \
                 devices pair --label LABEL --node UUID`",
                credential_root.join("device.credential").display(),
                config.paths.state_root.display()
            )
        })?;
    let client = ColinRemoteClient::with_limits(transport, credentials, limits);
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
        tokio::time::timeout(
            Duration::from_secs(10),
            connection.request_live(live_request),
        )
        .await
        .map_err(|_| "the terminal target request timed out".to_owned())?
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
    client: &ColinRemoteClient<EndpointTransport, FileCredentialStore>,
    command: live::LiveCommand,
) -> Result<live::CommandReceipt, String> {
    runtime.block_on(async {
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
    })
}
/// One session-command request without entering the runtime. Callers that
/// already hold a `block_on` use this so cleanup cannot nest another.
pub(super) async fn request_command(
    client: &ColinRemoteClient<EndpointTransport, FileCredentialStore>,
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

/// One live-list walk, cancellable by the caller's deadline. Absence is not
/// an error: exit cleanup falls back to the threaded operating epoch.
pub(super) async fn lookup_live_session(
    client: &ColinRemoteClient<EndpointTransport, FileCredentialStore>,
    session_id: live::LiveSessionId,
) -> Result<Option<live::LiveSessionSummary>, String> {
    let mut connection = client.connect().await.map_err(|error| error.to_string())?;
    let mut cursor: Option<live::SessionListCursor> = None;
    loop {
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            connection.request_live(live::LiveClientRequest::ListSessions {
                request_id: live_request_id()?,
                seat_id: None,
                include_ended: false,
                cursor,
                limit: NonZeroU16::new(128).expect("positive"),
            }),
        )
        .await
        .map_err(|_| "the session list request timed out".to_owned())?
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

/// Exit Abort for the current epoch: one list refetch, one send, and one
/// `EpochMismatch` retry. The caller bounds the whole future. A failed or
/// absent refetch keeps `epoch` (the chat loop's operating epoch), never an
/// attach-time snapshot stored elsewhere.
pub(super) async fn abort_current_epoch(
    client: &ColinRemoteClient<EndpointTransport, FileCredentialStore>,
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

/// Locates one live session by identity through the controller's real
/// session list, following the pagination cursor until the id is found or
/// the list is exhausted. Ended and failed sessions are excluded by the
/// query: attaching requires a live conversation partner. A session's tab is
/// created during the session's own launch, so the tab's attach client can
/// finish its first walk before the supervisor registers the new actor: the
/// lookup keeps walking through a bounded launch window instead of failing
/// on that race, while genuine absence after the window keeps the typed
/// not-live refusal.
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
    let started = Instant::now();
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

pub(super) fn find_live_session(
    runtime: &tokio::runtime::Runtime,
    client: &ColinRemoteClient<EndpointTransport, FileCredentialStore>,
    session_id: live::LiveSessionId,
) -> Result<live::LiveSessionSummary, String> {
    runtime.block_on(async {
        let shared = std::sync::Arc::new(tokio::sync::Mutex::new(
            client.connect().await.map_err(|error| error.to_string())?,
        ));
        retry_through_launch_window(
            {
                let shared = std::sync::Arc::clone(&shared);
                move || {
                    let shared = std::sync::Arc::clone(&shared);
                    async move {
                        let mut connection = shared.lock().await;
                        let mut cursor: Option<live::SessionListCursor> = None;
                        loop {
                            let response = tokio::time::timeout(
                                Duration::from_secs(10),
                                connection.request_live(live::LiveClientRequest::ListSessions {
                                    request_id: live_request_id()?,
                                    seat_id: None,
                                    include_ended: false,
                                    cursor,
                                    limit: NonZeroU16::new(128).expect("positive"),
                                }),
                            )
                            .await
                            .map_err(|_| "the session list request timed out".to_owned())?
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
                }
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
    fn endpoint_follows_the_declared_listener_and_tls() {
        let mut config_text = String::from(
            "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'laptop'\n[paths]\nregistry_root = '/'\nstate_root = '/'\nregistry_snapshot = '/'\nauthority_token_root = '/'\nauthority_verification_key_file = '/'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '",
        );
        config_text.push_str(&"a".repeat(40));
        config_text.push_str(
            "'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_session = 'odin'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:",
        );
        config_text.push_str(&"c".repeat(64));
        config_text.push_str(
            "'\n[publish]\nrender_session = 'live'\nfile_lane = 'f'\nrender_lane = 'r'\n[capacity]\n",
        );
        let config = OdindConfig::parse(&config_text).expect("minimal config parses");
        let endpoint = endpoint_for(&config).unwrap();
        assert_eq!(endpoint.as_str(), "http://127.0.0.1:18420/");

        let mut tls = config.clone();
        tls.listener.tls_cert = Some(PathBuf::from("/cert.pem"));
        let error = endpoint_for(&tls).expect_err("half-configured TLS is rejected");
        assert!(error.contains("TLS"), "unexpected error: {error}");
        tls.listener.tls_key = Some(PathBuf::from("/key.pem"));
        let secure = endpoint_for(&tls).unwrap();
        assert_eq!(secure.as_str(), "https://127.0.0.1:18420/");
    }

    #[test]
    fn generated_command_ids_are_unique_and_valid() {
        let first = generated_command_id().unwrap();
        let second = generated_command_id().unwrap();
        assert_ne!(first, second);
        assert!(live::LiveSessionId::parse(first.as_str()).is_ok());
    }

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
    fn attach_lookup_ends_with_absence_after_the_launch_window() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let walks = std::sync::atomic::AtomicU8::new(0);
        let found = runtime
            .block_on(retry_through_launch_window::<u32, _, _>(
                || async {
                    walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(None)
                },
                Duration::from_millis(20),
                Duration::from_millis(5),
            ))
            .unwrap();
        assert_eq!(found, None, "genuine absence ends as absence");
        let walked = walks.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            (2..=8).contains(&walked),
            "bounded retry near window/poll, walked {walked} times"
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
