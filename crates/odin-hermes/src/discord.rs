//! Discord REST and Gateway v10 transport using reqwest and tokio-tungstenite with rustls.
//!
//! Credential values are resolved at call time and excluded from envelopes, logs, and Debug output.
//! Sessions resume from READY identity and sequence when allowed; fatal close codes are not retried.

use std::fmt;

mod ratelimit;

use async_trait::async_trait;
use odin_domain::huginn::OpaqueCredentialHandle;
use serde_json::{json, Value};

/// Pinned Discord HTTPS REST API base (protocol version is part of the path).
pub const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

/// Pinned Discord Gateway endpoint (protocol version and encoding pinned).
pub const DISCORD_GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";

/// Gateway intent bit for direct messages (paired DM surface). Note this is
/// NOT `GUILD_MESSAGES` (1 << 9): the pinned Hermes policy serves DMs only,
/// groups and guilds are disabled.
pub const GATEWAY_INTENT_DIRECT_MESSAGES: u64 = 1 << 12;

/// Privileged gateway intent for message bodies. NOT part of the default:
/// requesting it without the developer-portal toggle fails IDENTIFY with
/// 4014 (Disallowed Intents), and DM message content is delivered without
/// it under Discord's message-content exemptions. Only request it when the
/// portal toggle is enabled and the operator renders it.
pub const GATEWAY_INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

/// Intents for the owner-paired DM surface: DIRECT_MESSAGES alone (4096).
/// Deployment facts stay configurable; a portal-enabled deployment may
/// render the MESSAGE_CONTENT bit on top. Verified in tests.
pub const DEFAULT_GATEWAY_INTENTS: u64 = GATEWAY_INTENT_DIRECT_MESSAGES;

/// Discord caps one channel message at 2000 UTF-8 code points; the egress
/// sink splits longer logical replies into consecutive messages so no
/// single send exceeds it.
pub const MAX_MESSAGE_CODEPOINTS: usize = 2000;

/// Discord's code for a message id that no longer exists. Deleting an
/// already-deleted tail chunk is settled, not a failure.
pub const UNKNOWN_MESSAGE_CODE: i64 = 10008;

/// The bearer value of a Discord bot token. `Debug` is manually redacted, the
/// value has no `Display` or serde exposure, and it must only be constructed
/// by the runtime that resolved it from the sops-rendered secret source.
pub struct SecretToken(String);

impl SecretToken {
    pub fn new(value: impl Into<String>) -> Result<Self, DiscordSendError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DiscordSendError::CredentialsUnavailable);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

/// The credential a transport call may use. `Absent` is a first-class state:
/// unconfigured deployments produce typed unavailable outcomes, never faked
/// success. `Token` carries the safe handle (log/envelope safe) plus the
/// runtime-resolved secret value that never leaves this process boundary.
#[derive(Debug)]
pub enum DiscordCredential {
    Token {
        handle: OpaqueCredentialHandle,
        secret: SecretToken,
    },
    Absent,
}

impl DiscordCredential {
    pub fn token(handle: OpaqueCredentialHandle, secret: SecretToken) -> Self {
        Self::Token { handle, secret }
    }

    pub fn absent() -> Self {
        Self::Absent
    }

    /// The safe credential identity, safe to log or reference in envelopes.
    pub fn handle(&self) -> Option<&OpaqueCredentialHandle> {
        match self {
            Self::Token { handle, .. } => Some(handle),
            Self::Absent => None,
        }
    }

    fn bearer(&self) -> Result<&str, DiscordSendError> {
        match self {
            Self::Token { secret, .. } => Ok(secret.expose()),
            Self::Absent => Err(DiscordSendError::CredentialsUnavailable),
        }
    }
}

/// One owner-paired Discord message, already projected off the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordMessage {
    pub id: String,
    pub channel_id: String,
    pub author_id: String,
    pub guild_id: Option<String>,
    pub content: String,
    /// Files attached to the message, served from Discord's CDN.
    pub attachments: Vec<DiscordAttachment>,
}

/// One file attached to a message. The URL is confined to Discord's CDN
/// hosts at parse time; nothing else is ever fetched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordAttachment {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub url: String,
    pub content_type: Option<String>,
}

/// The only hosts an attachment URL may name.
const ATTACHMENT_HOSTS: [&str; 2] = ["cdn.discordapp.com", "media.discordapp.net"];

fn parse_attachment(value: &Value) -> Option<DiscordAttachment> {
    let url = value.get("url")?.as_str()?;
    let host = url::Url::parse(url).ok()?;
    if host.scheme() != "https" || !ATTACHMENT_HOSTS.contains(&host.host_str()?) {
        return None;
    }
    let filename = value.get("filename")?.as_str()?;
    if filename.is_empty() || filename.len() > 255 {
        return None;
    }
    Some(DiscordAttachment {
        id: required_snowflake(value.get("id"))?,
        filename: filename.to_owned(),
        size: value.get("size")?.as_u64()?,
        url: url.to_owned(),
        content_type: value
            .get("content_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Parses a real Gateway `MESSAGE_CREATE` dispatch payload (`t == 0` envelope
/// `d` object). Returns `None` for anything that is not a usable channel
/// message; DM messages carry no `guild_id`.
pub fn parse_message_create(payload: &Value) -> Option<DiscordMessage> {
    let id = required_snowflake(payload.get("id"))?;
    let channel_id = required_snowflake(payload.get("channel_id"))?;
    let author = payload.get("author")?;
    let author_id = required_snowflake(author.get("id"))?;
    let guild_id = match payload.get("guild_id") {
        None | Some(Value::Null) => None,
        Some(value) => Some(required_snowflake(Some(value))?).filter(|id| !id.is_empty()),
    };
    let content = match payload.get("content") {
        None => String::new(),
        Some(Value::String(content)) => content.clone(),
        Some(_) => return None,
    };
    let attachments = payload
        .get("attachments")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_attachment).collect())
        .unwrap_or_default();
    Some(DiscordMessage {
        id,
        channel_id,
        author_id,
        guild_id,
        content,
        attachments,
    })
}

fn required_snowflake(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(id))
            if !id.is_empty() && id.len() <= 32 && id.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some(id.clone())
        }
        _ => None,
    }
}

/// A reference to a message the transport actually posted upstream.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DiscordMessageRef {
    pub message_id: String,
    pub channel_id: String,
}

/// Typed transport failures. None of them is a success; the caller decides
/// whether an outcome is retryable. `Debug` is derived and carries no
/// credential material.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscordSendError {
    #[error("discord credentials are not configured")]
    CredentialsUnavailable,
    #[error("the pinned Hermes deployment owns the discord gateway; odind must not identify a second listener")]
    GatewayNotOwned,
    #[error("discord transport is unavailable")]
    ServiceUnavailable,
    /// The connection to Discord failed before any request went out.
    #[error("discord could not be reached")]
    Unreachable,
    #[error("discord rate limited the request; retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("discord rejected the message with code {code}: {message}")]
    Rejected { code: i64, message: String },
    #[error("discord response could not be decoded")]
    Encoding,

    /// The gateway WebSocket could not be dialed at all (DNS, TCP, TLS, or
    /// HTTP upgrade). The cause text is transport-authored; the bearer
    /// value never travels in a URL, so no credential material can appear.
    #[error("the discord gateway websocket could not be connected: {cause}")]
    GatewayConnectFailed { cause: String },
    /// The established gateway socket ended cleanly without a Discord close
    /// frame and without a transport error: an EOF or a close frame that
    /// carried no code. Real read/write failures are
    /// [`DiscordSendError::GatewaySocketFailed`].
    #[error("the discord gateway connection was lost mid-session")]
    GatewayConnectionLost,
    /// A real WebSocket read/write failure mid-session, carried with the
    /// session phase it happened in and the transport-authored cause. The
    /// bearer value never travels in a URL, so no credential material can
    /// appear in the cause.
    #[error("the discord gateway socket failed during the {phase} phase: {cause}")]
    GatewaySocketFailed { phase: GatewayPhase, cause: String },
    /// Discord closed the session with a recoverable close code: the
    /// listener reconnects under the existing bounded policy, resuming
    /// whenever session state allows. The wire reason is carried verbatim.
    #[error("discord closed the gateway session with code {code}: {reason}")]
    GatewayClosed { code: u16, reason: String },
    /// Discord closed the session with a fatal close code (4004, 4010-4014):
    /// the documented remedy is operator action, never a reconnect. The
    /// close code and reason are preserved so supervision surfaces the real
    /// cause once and stops retrying.
    #[error("discord closed the gateway session fatally with code {code}: {reason}")]
    GatewayFatalClose { code: u16, reason: String },
    /// The connection never delivered the mandatory HELLO frame: a hung or
    /// misbehaving gateway handshake.
    #[error("the discord gateway did not provide the required HELLO")]
    GatewayHelloMissing,
    /// A heartbeat went unacknowledged past the next heartbeat deadline:
    /// a zombie socket per the gateway protocol.
    #[error("the discord gateway heartbeat went unacknowledged; the session is a zombie")]
    GatewayHeartbeatAckMissing,
    /// Discord requested a reconnect (op 7): the session ends and the
    /// listener reconnects, resuming when session state allows.
    #[error("discord requested a gateway reconnect")]
    GatewayReconnectRequested,
    /// Discord invalidated the session (op 9): a resumable session RESUMEs
    /// on the next connection; otherwise the listener identifies fresh.
    #[error("discord invalidated the gateway session (resumable: {resumable})")]
    GatewayInvalidSession { resumable: bool },
    /// The gateway violated the pinned session protocol: a required frame
    /// was malformed (a READY without its resumable identity, a HELLO
    /// without a strictly positive heartbeat interval). The honest recovery
    /// is a fresh session, never a fabricated identity or a guessed policy.
    #[error("the discord gateway violated the session protocol: {detail}")]
    GatewayProtocolViolation { detail: String },
}

/// The phase of a gateway session, for typed socket-failure reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayPhase {
    /// Awaiting the mandatory HELLO after connecting.
    Hello,
    /// Sending IDENTIFY or RESUME after HELLO.
    Handshake,
    /// Serving dispatches and heartbeats.
    Serving,
}

impl fmt::Display for GatewayPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Hello => "hello",
            Self::Handshake => "handshake",
            Self::Serving => "serving",
        })
    }
}

impl DiscordSendError {
    /// Fatal gateway close codes never reconnect. Derived from the official
    /// gateway close-event-code table (reconnect=false column):
    /// https://discord.com/developers/docs/topics/opcodes-and-status-codes.
    fn is_fatal_gateway_close(&self) -> bool {
        matches!(self, Self::GatewayFatalClose { .. })
    }

    /// Session-ending conditions that also invalidate the stored session
    /// state: a non-resumable invalid-session, and the closes the gateway
    /// answers with when the session or its sequence is gone.
    fn invalidates_gateway_session(&self) -> bool {
        match self {
            Self::GatewayInvalidSession { resumable: false } => true,
            Self::GatewayClosed {
                code: 4007 | 4009, ..
            } => true,
            // A malformed protocol frame poisons the stored identity: the
            // fresh session that follows must identify, not resume.
            Self::GatewayProtocolViolation { .. } => true,
            _ => false,
        }
    }
}

/// Whether a wire close code must stop reconnection, per the official
/// gateway close-event-code table (4004 authentication failed; 4010 invalid
/// shard; 4011 sharding required; 4012 invalid API version; 4013 invalid
/// intents; 4014 disallowed intents).
fn is_fatal_gateway_close_code(code: u16) -> bool {
    code == 4004 || (4010..=4014).contains(&code)
}

/// Plain WebSocket requires an exact localhost or parsed loopback host, without userinfo.
fn is_loopback_ws_target(gateway_url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(gateway_url) else {
        return false;
    };
    if parsed.scheme() != "ws" || !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Rejects credentials and transport downgrades in resume URLs, preserving configured version/encoding.
fn resume_endpoint(
    configured_gateway_url: &str,
    resume_gateway_url: &str,
) -> Result<String, DiscordSendError> {
    let configured = reqwest::Url::parse(configured_gateway_url).map_err(|_| {
        DiscordSendError::GatewayProtocolViolation {
            detail: "the configured gateway url is invalid".to_owned(),
        }
    })?;
    let mut url = reqwest::Url::parse(resume_gateway_url).map_err(|_| {
        DiscordSendError::GatewayProtocolViolation {
            detail: "READY resume_gateway_url is not a valid URL".to_owned(),
        }
    })?;
    if !matches!(url.scheme(), "ws" | "wss") {
        return Err(DiscordSendError::GatewayProtocolViolation {
            detail: "READY resume_gateway_url is not a ws/wss endpoint".to_owned(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DiscordSendError::GatewayProtocolViolation {
            detail: "READY resume_gateway_url carries credential material".to_owned(),
        });
    }
    if url.scheme() != configured.scheme()
        || (url.scheme() == "ws" && !is_loopback_ws_target(url.as_str()))
    {
        return Err(DiscordSendError::GatewayProtocolViolation {
            detail: "READY resume_gateway_url must not change the configured transport; \
                     plain ws is only the loopback test transport"
                .to_owned(),
        });
    }
    if url.query().is_none() {
        let query = configured.query().map(str::to_owned);
        url.set_query(query.as_deref());
    }
    Ok(url.to_string())
}

/// Maps a wire close frame onto the typed close causes: fatal codes surface
/// once without a further attempt; every other code reconnects under the
/// existing bounded policy. The wire reason is carried verbatim, even when
/// empty.
fn gateway_close_error(code: u16, reason: &str) -> DiscordSendError {
    let reason = reason.to_owned();
    if is_fatal_gateway_close_code(code) {
        DiscordSendError::GatewayFatalClose { code, reason }
    } else {
        DiscordSendError::GatewayClosed { code, reason }
    }
}

/// The Discord send port. Production binds [`DiscordRestTransport`]; the
/// egress publisher depends only on this trait.
#[async_trait]
pub trait DiscordTransport: Send + Sync {
    async fn send_message(
        &self,
        channel_id: &str,
        content: &str,
    ) -> Result<DiscordMessageRef, DiscordSendError>;

    /// Replaces the content of a message this bot posted.
    async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        content: &str,
    ) -> Result<DiscordMessageRef, DiscordSendError>;

    /// Deletes a message this bot posted. Deleting an already-deleted
    /// message is reported as [`DiscordSendError::Rejected`] with
    /// [`UNKNOWN_MESSAGE_CODE`].
    async fn delete_message(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<(), DiscordSendError>;

    /// Shows "typing…" in the channel for about ten seconds.
    async fn trigger_typing(&self, channel_id: &str) -> Result<(), DiscordSendError>;
}

/// The bounded catch-up window: at most this many DM history entries are
/// fetched per reconnect catch-up pass.
pub const DM_CATCH_UP_LIMIT: u32 = 50;

/// The real Discord REST transport. Every call performs an actual HTTPS
/// request against the pinned API base; nothing is simulated.
pub struct DiscordRestTransport {
    credential: DiscordCredential,
    http: reqwest::Client,
    api_base: String,
    limits: ratelimit::RateGate,
    /// `Bot <token>`, built once. `None` when the credential is absent, so
    /// every send still fails [`DiscordSendError::CredentialsUnavailable`]
    /// without formatting the header on the call.
    authorization: Option<String>,
}

impl DiscordRestTransport {
    /// Production constructor bound to the pinned `https://discord.com/api/v10`.
    pub fn new(credential: DiscordCredential) -> Self {
        Self::with_http(credential, reqwest::Client::new())
    }

    pub fn with_http(credential: DiscordCredential, http: reqwest::Client) -> Self {
        let authorization = cached_authorization(&credential);
        Self {
            credential,
            http,
            api_base: DISCORD_API_BASE.to_owned(),
            limits: ratelimit::RateGate::default(),
            authorization,
        }
    }

    /// Binds a different API base. Only the pinned production base and
    /// loopback admission targets are accepted so this can never silently
    /// point the transport at an arbitrary remote host.
    pub fn with_api_base(
        credential: DiscordCredential,
        http: reqwest::Client,
        api_base: impl Into<String>,
    ) -> Result<Self, DiscordSendError> {
        let api_base = api_base.into();
        let loopback = api_base.starts_with("http://127.0.0.1")
            || api_base.starts_with("http://localhost")
            || api_base.starts_with("http://[::1]");
        if !api_base.starts_with("https://") && !loopback {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: "discord api base must use https (loopback http is admitted for tests)"
                    .to_owned(),
            });
        }
        let authorization = cached_authorization(&credential);
        Ok(Self {
            credential,
            http,
            api_base,
            limits: ratelimit::RateGate::default(),
            authorization,
        })
    }

    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    pub async fn fetch_delivery_message(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<Option<DiscordMessage>, DiscordSendError> {
        for parameter in [channel_id, message_id] {
            if parameter.is_empty()
                || parameter.len() > 32
                || !parameter.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(DiscordSendError::Rejected {
                    code: 0,
                    message: "channel and message parameters must be decimal snowflakes".into(),
                });
            }
        }
        let path = format!("/channels/{channel_id}/messages/{message_id}");
        let body = self
            .delivery_get(&path, &format!("GET message {channel_id}"), true)
            .await?;
        body.map(|body| parse_message_create(&body).ok_or(DiscordSendError::Encoding))
            .transpose()
    }

    pub async fn delivery_bot_user_id(&self) -> Result<String, DiscordSendError> {
        let body = self
            .delivery_get("/users/@me", "GET current user", false)
            .await?
            .ok_or(DiscordSendError::Encoding)?;
        if body.get("bot").and_then(Value::as_bool) != Some(true) {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: "delivery reconciliation requires the authenticated bot account".into(),
            });
        }
        body.get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_owned)
            .ok_or(DiscordSendError::Encoding)
    }

    async fn delivery_get(
        &self,
        path: &str,
        route: &str,
        missing_message: bool,
    ) -> Result<Option<Value>, DiscordSendError> {
        let authorization = self.authorization()?;
        let url = format!("{}{path}", self.api_base);
        let response = self
            .limits
            .send(route, || {
                self.http.get(&url).header("Authorization", authorization)
            })
            .await?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(Some(body));
        }
        if missing_message
            && status.as_u16() == 404
            && body.get("code").and_then(Value::as_i64) == Some(UNKNOWN_MESSAGE_CODE)
        {
            return Ok(None);
        }
        if status.as_u16() == 429 {
            return Err(DiscordSendError::RateLimited {
                retry_after_ms: body
                    .get("retry_after")
                    .and_then(Value::as_f64)
                    .map(|seconds| (seconds * 1000.0).round() as u64)
                    .unwrap_or(0),
            });
        }
        if status.is_server_error() {
            return Err(DiscordSendError::ServiceUnavailable);
        }
        Err(DiscordSendError::Rejected {
            code: body.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown rejection")
                .to_owned(),
        })
    }

    /// Fetches the channel's message history strictly AFTER `after`
    /// (exclusive snowflake cursor; `None` starts from the newest bounded
    /// window), returning messages OLDEST FIRST so each admits through the
    /// live intake path in arrival order. This is the reconnect catch-up
    /// seam: Discord's gateway never replays `MESSAGE_CREATE` events a
    /// down or starting authority missed, so the durable intake cursor
    /// (the idempotency-key state) plus this bounded backfill is the only
    /// recovery path. Idempotency at admit makes a replayed fetch safe.
    pub async fn fetch_messages_after(
        &self,
        channel_id: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<DiscordMessage>, DiscordSendError> {
        for parameter in std::iter::once(channel_id).chain(after) {
            if parameter.is_empty()
                || parameter.len() > 32
                || !parameter.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(DiscordSendError::Rejected {
                    code: 0,
                    message: "channel and cursor parameters must be decimal snowflakes".to_owned(),
                });
            }
        }
        let limit = limit.clamp(1, DM_CATCH_UP_LIMIT);
        let bearer = self.credential.bearer()?;
        let mut url = format!(
            "{}/channels/{channel_id}/messages?limit={limit}",
            self.api_base
        );
        if let Some(after) = after {
            url.push_str("&after=");
            url.push_str(after);
        }
        let response = self
            .limits
            .send(&format!("GET messages {channel_id}"), || {
                self.http
                    .get(&url)
                    .header("Authorization", format!("Bot {bearer}"))
            })
            .await?;
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            if status.as_u16() == 429 {
                let retry_after_ms = body
                    .get("retry_after")
                    .and_then(Value::as_f64)
                    .map(|seconds| (seconds * 1000.0).round() as u64)
                    .unwrap_or(0);
                return Err(DiscordSendError::RateLimited { retry_after_ms });
            }
            if status.is_server_error() {
                return Err(DiscordSendError::ServiceUnavailable);
            }
            return Err(DiscordSendError::Rejected {
                code: body.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: body
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown rejection")
                    .to_owned(),
            });
        }
        let entries = body.as_array().ok_or(DiscordSendError::Encoding)?;
        let mut messages = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(message) = parse_message_create(entry) {
                messages.push(message);
            }
        }
        // Discord returns the newest window first; intake order is oldest
        // first so answers follow question order.
        messages.reverse();
        Ok(messages)
    }
}

/// The largest file one message carries (Discord's default upload limit).
pub const MAX_FILE_BYTES: usize = 10 * 1024 * 1024;

impl DiscordRestTransport {
    /// Posts one message carrying one file. The multipart body is built by
    /// hand — a `payload_json` part and one `files[0]` part — so no extra
    /// HTTP feature is linked.
    pub async fn send_file(
        &self,
        channel_id: &str,
        content: &str,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<DiscordMessageRef, DiscordSendError> {
        if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: format!("a file must be 1..={MAX_FILE_BYTES} bytes"),
            });
        }
        if content.chars().count() > MAX_MESSAGE_CODEPOINTS {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: "message content exceeds the Discord code point limit".to_owned(),
            });
        }
        let file_name: String = file_name
            .chars()
            .map(|c| {
                if c.is_ascii_graphic() && c != '"' && c != '\\' {
                    c
                } else {
                    '_'
                }
            })
            .take(120)
            .collect();
        let boundary = format!(
            "odin-{}",
            odin_domain::Digest::hash(bytes)
                .to_string()
                .trim_start_matches("blake3:")
                .get(..24)
                .unwrap_or("boundary")
        );
        let payload = json!({
            "content": content,
            "attachments": [{ "id": 0, "filename": file_name }],
        });
        let mut body = Vec::with_capacity(bytes.len() + 512);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\n\
                 Content-Type: application/json\r\n\r\n{payload}\r\n--{boundary}\r\n\
                 Content-Disposition: form-data; name=\"files[0]\"; filename=\"{file_name}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let bearer = self.credential.bearer()?;
        let url = format!("{}/channels/{channel_id}/messages", self.api_base);
        let response = self
            .limits
            .send(&format!("POST messages {channel_id}"), || {
                self.http
                    .post(&url)
                    .header("Authorization", format!("Bot {bearer}"))
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(body.clone())
            })
            .await?;
        settle_send(response, channel_id).await
    }
}

/// A message body Discord accepts: non-empty, within the code point bound.
fn checked_content(content: &str) -> Result<(), DiscordSendError> {
    if content.is_empty() {
        return Err(DiscordSendError::Rejected {
            code: 0,
            message: "message content must not be empty".to_owned(),
        });
    }
    if content.chars().count() > MAX_MESSAGE_CODEPOINTS {
        return Err(DiscordSendError::Rejected {
            code: 0,
            message: "message content exceeds the Discord code point limit".to_owned(),
        });
    }
    Ok(())
}

/// Maps one message-create or -edit response onto the transport's typed
/// outcome.
async fn settle_send(
    response: reqwest::Response,
    channel_id: &str,
) -> Result<DiscordMessageRef, DiscordSendError> {
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if status.is_success() {
        let message_id = body
            .get("id")
            .and_then(Value::as_str)
            .ok_or(DiscordSendError::Encoding)?
            .to_owned();
        let echoed_channel = body
            .get("channel_id")
            .and_then(Value::as_str)
            .unwrap_or(channel_id);
        return Ok(DiscordMessageRef {
            message_id,
            channel_id: echoed_channel.to_owned(),
        });
    }
    if status.as_u16() == 429 {
        let retry_after_ms = body
            .get("retry_after")
            .and_then(Value::as_f64)
            .map(|seconds| (seconds * 1000.0).round() as u64)
            .unwrap_or(0);
        return Err(DiscordSendError::RateLimited { retry_after_ms });
    }
    if status.is_server_error() {
        return Err(DiscordSendError::ServiceUnavailable);
    }
    Err(DiscordSendError::Rejected {
        code: body.get("code").and_then(Value::as_i64).unwrap_or(0),
        message: body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown rejection")
            .to_owned(),
    })
}

impl fmt::Debug for DiscordRestTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscordRestTransport")
            .field("credential", &self.credential)
            .field("api_base", &self.api_base)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DiscordTransport for DiscordRestTransport {
    async fn send_message(
        &self,
        channel_id: &str,
        content: &str,
    ) -> Result<DiscordMessageRef, DiscordSendError> {
        checked_content(content)?;
        let authorization = self.authorization()?;
        let url = format!("{}/channels/{channel_id}/messages", self.api_base);
        let body = content_body(content)?;
        let response = self
            .limits
            .send(&format!("POST messages {channel_id}"), || {
                self.http
                    .post(&url)
                    .header("Authorization", authorization)
                    .header("content-type", "application/json")
                    .body(body.clone())
            })
            .await?;
        settle_send(response, channel_id).await
    }

    async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        content: &str,
    ) -> Result<DiscordMessageRef, DiscordSendError> {
        checked_content(content)?;
        let authorization = self.authorization()?;
        let url = format!(
            "{}/channels/{channel_id}/messages/{message_id}",
            self.api_base
        );
        let body = content_body(content)?;
        let response = self
            .limits
            .send(&format!("PATCH messages {channel_id}"), || {
                self.http
                    .patch(&url)
                    .header("Authorization", authorization)
                    .header("content-type", "application/json")
                    .body(body.clone())
            })
            .await?;
        settle_send(response, channel_id).await
    }

    async fn trigger_typing(&self, channel_id: &str) -> Result<(), DiscordSendError> {
        let authorization = self.authorization()?;
        let url = format!("{}/channels/{channel_id}/typing", self.api_base);
        let response = self
            .limits
            .send(&format!("POST typing {channel_id}"), || {
                self.http
                    .post(&url)
                    .header("Authorization", authorization)
                    .header("Content-Length", "0")
            })
            .await?;
        match response.status() {
            status if status.is_success() => Ok(()),
            status if status.as_u16() == 429 => {
                Err(DiscordSendError::RateLimited { retry_after_ms: 0 })
            }
            status if status.is_server_error() => Err(DiscordSendError::ServiceUnavailable),
            status => Err(DiscordSendError::Rejected {
                code: i64::from(status.as_u16()),
                message: "typing indicator refused".to_owned(),
            }),
        }
    }

    async fn delete_message(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<(), DiscordSendError> {
        let authorization = self.authorization()?;
        let url = format!(
            "{}/channels/{channel_id}/messages/{message_id}",
            self.api_base
        );
        let response = self
            .limits
            .send(&format!("DELETE messages {channel_id}"), || {
                self.http
                    .delete(&url)
                    .header("Authorization", authorization)
            })
            .await?;
        match response.status() {
            status if status.is_success() => Ok(()),
            status if status.as_u16() == 429 => {
                Err(DiscordSendError::RateLimited { retry_after_ms: 0 })
            }
            status if status.is_server_error() => Err(DiscordSendError::ServiceUnavailable),
            status => Err(DiscordSendError::Rejected {
                code: i64::from(status.as_u16()),
                message: "message deletion refused".to_owned(),
            }),
        }
    }
}

fn cached_authorization(credential: &DiscordCredential) -> Option<String> {
    credential
        .bearer()
        .ok()
        .map(|bearer| format!("Bot {bearer}"))
}

fn content_body(content: &str) -> Result<Vec<u8>, DiscordSendError> {
    let mut body = Vec::with_capacity(content.len().saturating_add(13));
    body.extend_from_slice(br#"{"content":"#);
    serde_json::to_writer(&mut body, content).map_err(|_| DiscordSendError::Encoding)?;
    body.push(b'}');
    Ok(body)
}

impl DiscordRestTransport {
    fn authorization(&self) -> Result<&str, DiscordSendError> {
        self.authorization
            .as_deref()
            .ok_or(DiscordSendError::CredentialsUnavailable)
    }
}

/// Selects the sole gateway listener for the shared bot token; `HermesPinned` refuses Odin connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayOwnership {
    HermesPinned,
    Odin,
}

/// Bounded reconnect behavior for the Odin-owned listener: capped attempts
/// with capped exponential backoff. No unbounded loops, no faked liveness —
/// when the bound is exhausted the typed error surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    pub max_attempts: u32,
    pub initial_backoff: std::time::Duration,
    pub max_backoff: std::time::Duration,
}

impl ReconnectPolicy {
    /// The bounded default: five attempts, 1 s doubling up to 30 s.
    pub const fn bounded() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: std::time::Duration::from_secs(1),
            max_backoff: std::time::Duration::from_secs(30),
        }
    }

    fn validate(&self) -> Result<(), DiscordSendError> {
        if self.max_attempts == 0 || self.initial_backoff.is_zero() {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: "reconnect policy must allow at least one attempt with a positive backoff"
                    .to_owned(),
            });
        }
        if self.max_backoff < self.initial_backoff {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: "reconnect backoff ceiling must not be below the initial backoff"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn backoff_for(&self, attempt: u32) -> std::time::Duration {
        let shift = attempt.min(16);
        let scaled = self.initial_backoff.saturating_mul(1_u32 << shift);
        scaled.min(self.max_backoff)
    }
}

/// Receives owner-paired Discord messages from the production gateway listener.
pub trait DiscordIngressSink: Send + Sync {
    fn message(&self, message: DiscordMessage);
}

/// Bound on how long a gateway connection may fail to deliver its mandatory
/// HELLO before the handshake is declared hung.
const GATEWAY_HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The resumable session state Discord pins at READY: the session id, the
/// validated resume endpoint (already carrying the pinned connection
/// query), and the last dispatch sequence echoed in every heartbeat and
/// RESUME payload. Retained across session endings and cancellations so a
/// reconnect resumes instead of re-identifying whenever the protocol
/// allows it.
#[derive(Clone)]
struct GatewaySession {
    session_id: String,
    resume_gateway_url: String,
    last_sequence: Option<u64>,
}

/// The real Gateway v10 listener: connects, completes the HELLO handshake
/// with RESUME or IDENTIFY, answers heartbeats, and forwards
/// `MESSAGE_CREATE` dispatches to the sink. Sessions RESUME through the
/// READY-pinned identity and last sequence whenever the protocol allows
/// and identify fresh when they do not; reconnects stay bounded by the
/// supplied [`ReconnectPolicy`], and fatal close codes (4004, 4010-4014)
/// surface their typed cause once without any further attempt.
pub struct DiscordGateway {
    ownership: GatewayOwnership,
    credential: DiscordCredential,
    intents: u64,
    gateway_url: String,
    /// The resumable session state, retained across sessions and
    /// cancellations; `run` holds the lock across its whole loop, which
    /// also serializes concurrent runs.
    session: tokio::sync::Mutex<Option<GatewaySession>>,
}

impl fmt::Debug for DiscordGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscordGateway")
            .field("ownership", &self.ownership)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl DiscordGateway {
    /// Constructs the listener. `ownership` decides whether `run` may dial
    /// at all: the pinned Hermes deployment owns the live gateway on the
    /// shared token, so production composes [`GatewayOwnership::HermesPinned`].
    pub fn new(ownership: GatewayOwnership, credential: DiscordCredential, intents: u64) -> Self {
        Self {
            ownership,
            credential,
            intents,
            gateway_url: DISCORD_GATEWAY_URL.to_owned(),
            session: tokio::sync::Mutex::new(None),
        }
    }

    /// The composed credential's declared-presence status: `true` when the
    /// platform section exists but no credentials were provisioned, so a
    /// listener on this gateway can never dial and must stay disarmed.
    pub const fn credential_absent(&self) -> bool {
        matches!(self.credential, DiscordCredential::Absent)
    }

    /// Binds a different gateway endpoint. Only loopback `ws://` targets
    /// (`127.0.0.1`, `localhost`, `[::1]`) are accepted so a test listener
    /// can exercise the real handshake; the pinned production wss endpoint
    /// stays reachable exclusively through [`DiscordGateway::new`].
    pub fn with_gateway_url(
        ownership: GatewayOwnership,
        credential: DiscordCredential,
        intents: u64,
        gateway_url: impl Into<String>,
    ) -> Result<Self, DiscordSendError> {
        let gateway_url = gateway_url.into();
        let loopback = is_loopback_ws_target(&gateway_url);
        if !loopback {
            return Err(DiscordSendError::Rejected {
                code: 0,
                message: "gateway url override must be a loopback ws target (tests only)"
                    .to_owned(),
            });
        }
        Ok(Self {
            ownership,
            credential,
            intents,
            gateway_url,
            session: tokio::sync::Mutex::new(None),
        })
    }

    /// Runs the listener with bounded reconnect behavior. A non-owner
    /// returns the typed refusal before any connection attempt; missing
    /// credentials return the typed unavailable error likewise. Sessions
    /// RESUME when the gateway allows it and identify fresh when they do
    /// not; the resumable state survives both session endings and
    /// cancellations. A fatal gateway close (4004, 4010-4014) surfaces its
    /// typed cause once and stops the loop — never retried here.
    pub async fn run(
        &self,
        sink: std::sync::Arc<dyn DiscordIngressSink>,
        policy: ReconnectPolicy,
    ) -> Result<(), DiscordSendError> {
        policy.validate()?;
        if self.ownership != GatewayOwnership::Odin {
            return Err(DiscordSendError::GatewayNotOwned);
        }
        // One lock guard spans the whole reconnect loop: cancelling the run
        // drops the guard but leaves the state in the mutex, and concurrent
        // runs serialize on the lock.
        let mut session = self.session.lock().await;
        let mut attempt = 0;
        loop {
            let error = match self.run_session(sink.clone(), &mut session).await {
                ok @ Ok(()) => return ok,
                Err(error) => error,
            };
            // A fatal gateway close is an operator fact, not a transient:
            // the typed cause surfaces once and the listener stops.
            if error.is_fatal_gateway_close() {
                *session = None;
                return Err(error);
            }
            // Session-invalidating endings discard the resumable identity;
            // everything else keeps it so the next dial resumes.
            if error.invalidates_gateway_session() {
                *session = None;
            }
            attempt += 1;
            if attempt >= policy.max_attempts {
                return Err(error);
            }
            tokio::time::sleep(policy.backoff_for(attempt)).await;
        }
    }

    /// Serves one gateway session: dial (the READY-pinned resume endpoint
    /// when resuming), await HELLO, send RESUME or IDENTIFY, then answer
    /// heartbeats and dispatches until the session ends. Every ending
    /// carries its typed cause; the caller's guard owns the resumable
    /// state, so it survives cancellations and session endings.
    async fn run_session(
        &self,
        sink: std::sync::Arc<dyn DiscordIngressSink>,
        session: &mut Option<GatewaySession>,
    ) -> Result<(), DiscordSendError> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let bearer = self.credential.bearer()?.to_owned();
        // A resume dials the READY-pinned resume endpoint, already
        // validated and completed with the pinned connection query at
        // READY; a fresh session dials the configured gateway URL.
        let endpoint = match session.as_ref() {
            Some(state) => state.resume_gateway_url.as_str(),
            None => self.gateway_url.as_str(),
        };
        let (mut socket, _) =
            tokio_tungstenite::connect_async(endpoint)
                .await
                .map_err(|error| DiscordSendError::GatewayConnectFailed {
                    cause: error.to_string(),
                })?;

        // HELLO is the gateway's mandatory first frame; a connection that
        // fails to deliver one inside the deadline is a hung handshake.
        let first = match tokio::time::timeout(GATEWAY_HELLO_DEADLINE, socket.next()).await {
            Err(_) => return Err(DiscordSendError::GatewayHelloMissing),
            // A clean EOF before HELLO loses the connection without a
            // cause; a real transport failure carries its phase and cause.
            Ok(None) => return Err(DiscordSendError::GatewayConnectionLost),
            Ok(Some(Err(error))) => {
                return Err(DiscordSendError::GatewaySocketFailed {
                    phase: GatewayPhase::Hello,
                    cause: error.to_string(),
                })
            }
            Ok(Some(Ok(message))) => message,
        };
        let hello = match first {
            Message::Text(text) => text,
            Message::Close(Some(close)) => {
                return Err(gateway_close_error(
                    u16::from(close.code),
                    close.reason.as_str(),
                ))
            }
            Message::Close(None) => return Err(DiscordSendError::GatewayConnectionLost),
            _ => return Err(DiscordSendError::GatewayHelloMissing),
        };
        let hello: Value = serde_json::from_str(&hello).map_err(|_| DiscordSendError::Encoding)?;
        if hello.get("op").and_then(Value::as_u64) != Some(10) {
            // A dispatch, heartbeat, or invalid session cannot start a
            // session: the gateway failed to begin the handshake.
            return Err(DiscordSendError::GatewayHelloMissing);
        }
        // The interval is required wire evidence: a HELLO without a
        // strictly positive one cannot be heartbeated safely and is
        // refused, never guessed.
        let heartbeat_interval = hello
            .pointer("/d/heartbeat_interval")
            .and_then(Value::as_u64)
            .filter(|milliseconds| *milliseconds > 0)
            .ok_or_else(|| DiscordSendError::GatewayProtocolViolation {
                detail: "HELLO carried no strictly positive heartbeat_interval".to_owned(),
            })?;
        let mut heartbeat =
            tokio::time::interval(std::time::Duration::from_millis(heartbeat_interval));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The fresh interval's first tick fires immediately; consume it so
        // the first scheduled heartbeat lands a full interval after the
        // handshake instead of racing the READY exchange.
        heartbeat.tick().await;

        // Handshake: RESUME when resumable session state exists, else a
        // fresh IDENTIFY.
        let handshake = match session.as_ref() {
            Some(state) => json!({
                "op": 6,
                "d": {
                    "token": &bearer,
                    "session_id": state.session_id,
                    "seq": state.last_sequence,
                },
            }),
            None => json!({
                "op": 2,
                "d": {
                    "token": &bearer,
                    "intents": self.intents,
                    "properties": {
                        "os": "linux",
                        "browser": "odin-hermes",
                        "device": "odin-hermes",
                    },
                },
            }),
        };
        if let Err(error) = socket
            .send(Message::Text(handshake.to_string().into()))
            .await
        {
            return Err(DiscordSendError::GatewaySocketFailed {
                phase: GatewayPhase::Handshake,
                cause: error.to_string(),
            });
        }

        // A heartbeat left un-acknowledged by the next tick means a zombie
        // socket; the session is terminated for a resume.
        let mut heartbeat_acked = true;
        // Every received op0 dispatch pins its sequence for heartbeats —
        // independently of whether a valid READY identity exists for
        // RESUME: the heartbeat echoes the wire's last sequence and never
        // fabricates session identity. A resumed session starts from its
        // persisted sequence.
        let mut last_dispatch_sequence = session.as_ref().and_then(|state| state.last_sequence);
        loop {
            let frame = tokio::select! {
                _ = heartbeat.tick() => {
                    if !heartbeat_acked {
                        // The previous heartbeat was never acknowledged: the
                        // socket is a zombie. Ending without a WS close keeps
                        // the session resumable per the disconnect rules.
                        return Err(DiscordSendError::GatewayHeartbeatAckMissing);
                    }
                    let sequence = last_dispatch_sequence;
                    let payload = json!({ "op": 1, "d": sequence }).to_string();
                    if let Err(error) = socket.send(Message::Text(payload.into())).await {
                        return Err(DiscordSendError::GatewaySocketFailed {
                            phase: GatewayPhase::Serving,
                            cause: error.to_string(),
                        });
                    }
                    heartbeat_acked = false;
                    continue;
                }
                frame = socket.next() => match frame {
                    Some(Ok(message)) => message,
                    // A clean EOF loses the connection without a cause; a
                    // real read failure carries its phase and cause.
                    None => return Err(DiscordSendError::GatewayConnectionLost),
                    Some(Err(error)) => {
                        return Err(DiscordSendError::GatewaySocketFailed {
                            phase: GatewayPhase::Serving,
                            cause: error.to_string(),
                        })
                    }
                },
            };
            let text = match frame {
                Message::Text(text) => text,
                Message::Close(Some(close)) => {
                    return Err(gateway_close_error(
                        u16::from(close.code),
                        close.reason.as_str(),
                    ))
                }
                Message::Close(None) => return Err(DiscordSendError::GatewayConnectionLost),
                _ => continue,
            };
            let value: Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => return Err(DiscordSendError::Encoding),
            };
            match value.get("op").and_then(Value::as_u64) {
                // Heartbeat ACK.
                Some(11) => heartbeat_acked = true,
                // Server-requested heartbeat: answer immediately.
                Some(1) => {
                    let sequence = last_dispatch_sequence;
                    let payload = json!({ "op": 1, "d": sequence }).to_string();
                    if let Err(error) = socket.send(Message::Text(payload.into())).await {
                        return Err(DiscordSendError::GatewaySocketFailed {
                            phase: GatewayPhase::Serving,
                            cause: error.to_string(),
                        });
                    }
                    heartbeat_acked = false;
                }
                // Dispatch: pin the sequence for heartbeats and RESUME, pin
                // the session identity at READY, then project messages.
                Some(0) => {
                    let sequence = value.get("s").and_then(Value::as_u64);
                    if let Some(sequence) = sequence {
                        last_dispatch_sequence = Some(sequence);
                    }
                    if let (Some(state), Some(sequence)) = (session.as_mut(), sequence) {
                        state.last_sequence = Some(sequence);
                    }
                    match value.get("t").and_then(Value::as_str) {
                        Some("READY") => {
                            // The resumable identity is required wire
                            // evidence: a READY missing any of it is refused
                            // typed — never resumed with a fabricated
                            // identity or a fallback endpoint.
                            let session_id = value
                                .pointer("/d/session_id")
                                .and_then(Value::as_str)
                                .filter(|id| !id.is_empty());
                            let resume_gateway_url = value
                                .pointer("/d/resume_gateway_url")
                                .and_then(Value::as_str)
                                .filter(|url| !url.is_empty());
                            let (Some(session_id), Some(resume_gateway_url), Some(sequence)) =
                                (session_id, resume_gateway_url, sequence)
                            else {
                                let mut missing = Vec::new();
                                if session_id.is_none() {
                                    missing.push("session_id");
                                }
                                if resume_gateway_url.is_none() {
                                    missing.push("resume_gateway_url");
                                }
                                if sequence.is_none() {
                                    missing.push("dispatch sequence");
                                }
                                return Err(DiscordSendError::GatewayProtocolViolation {
                                    detail: format!("READY is missing {}", missing.join(", ")),
                                });
                            };
                            let resume_url =
                                resume_endpoint(&self.gateway_url, resume_gateway_url)?;
                            *session = Some(GatewaySession {
                                session_id: session_id.to_owned(),
                                resume_gateway_url: resume_url,
                                last_sequence: Some(sequence),
                            });
                        }
                        Some("MESSAGE_CREATE") => {
                            if let Some(d) = value.get("d") {
                                if let Some(message) = parse_message_create(d) {
                                    sink.message(message);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // Server-requested reconnect: end the session; the reconnect
                // loop redials the resume endpoint and RESUMEs when session
                // state exists.
                Some(7) => return Err(DiscordSendError::GatewayReconnectRequested),
                // Invalid session: resumable sessions RESUME on the next
                // connection; otherwise the stored state is dead and the
                // listener identifies fresh.
                Some(9) => {
                    let resumable = value.get("d").and_then(Value::as_bool).unwrap_or(false);
                    return Err(DiscordSendError::GatewayInvalidSession { resumable });
                }
                _ => {}
            }
        }
    }
}
/// Orders Discord snowflakes by their timestamp component. The lower 22 bits
/// identify workers/processes and local counters, not a global creation order.
/// Same-millisecond messages cannot prove that the reply followed the question.
/// See https://discord.com/developers/docs/reference#snowflakes.
pub(super) fn transport_message_order(reply: &str, question: &str) -> Option<std::cmp::Ordering> {
    let (reply, question) = (reply.parse::<u64>().ok()?, question.parse::<u64>().ok()?);
    Some((reply >> 22).cmp(&(question >> 22)))
}

#[cfg(test)]
mod content_body_tests {
    use serde_json::json;

    use super::content_body;

    #[test]
    fn content_body_matches_the_json_object_serde_emits() {
        for content in ["hi", "a \"quote\"\nline", "unicode \u{2603}", ""] {
            let body = content_body(content).expect("encode");
            let expected = serde_json::to_vec(&json!({"content": content})).expect("serde");
            assert_eq!(body, expected, "{content}");
        }
    }
}
