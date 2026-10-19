//! IMAP/SMTP mail with an independently authenticated optional CalDAV calendar.
//!
//! Deployment endpoints, mailboxes, credentials, deadlines, and limits come from configuration.
//! Mail uses XOAUTH2 and stable IMAP UIDs; STARTTLS endpoints upgrade before sending credentials or content.
//! CalDAV requires HTTPS except on loopback and never follows redirects. Cancellation changes status,
//! not deletion; mail deletion and unsubscribing are also unsupported.
//! Credentials use private `0600` files and redacted wrappers excluded from serialization.
//!
//! Credential file schema (written by `odin account login
//! microsoft-mail` and extended by `odin account configure-caldav`,
//! resolved by `resolve_mail_credentials`):
//! ```json
//! {
//!   "version": 1,
//!   "account": "colin@example.com",
//!   "user": "colin@example.com",
//!   "access_token": "<XOAUTH2 bearer for IMAP/SMTP/direct CalDAV>",
//!   "expires_at": "<RFC 3339 UTC instant of access expiry>",
//!   "refresh_token": "<Microsoft refresh grant; required>",
//!   "client_id": "<Microsoft OAuth client id; required>",
//!   "tenant": "<common | tenant id | domain; required>",
//!   "caldav_basic": { "user": "calendar-user", "password": "<app token>" }
//! }
//! ```
//!
//! The refresh quartet (`expires_at`, `refresh_token`, `client_id`,
//! `tenant`) is required — a bundle that cannot refresh is not a
//! usable deployment fact. The grant is provider-owned: before every
//! mail or
//! calendar exchange, an access token expiring within 60 seconds is
//! refreshed once against the tenant v2 token endpoint (HTTPS,
//! redirects off, bounded response), the rotated refresh token is kept
//! when returned, and the bundle is atomically rewritten at mode 0600.
//! A refresh failure is a typed credentials fault; there is no retry.
//! `version` must be `1`; `account` must equal the configured account
//! and the lease account (the file-binding check); `user` is the SASL
//! user framed into XOAUTH2; `access_token` is the bearer presented as
//! `auth=Bearer` in the XOAUTH2 frame. The optional `caldav_basic`
//! object carries a distinct CalDAV Basic pair for either loopback HTTP
//! or remote HTTPS; the password never enters configuration, envelopes,
//! or logs.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use odin_domain::huginn::OpaqueCredentialHandle;
use odin_domain::CapabilityId;

use crate::account::{
    AccountSecretRef, AccountUnavailable, BatchFault, ScopedCredentialLease, TransportFault,
    MAX_ACCOUNT_CHARS,
};
use crate::calendar::{
    CalendarEventDraft, CalendarEventSummary, CalendarMutation, CalendarMutationReceipt,
    CalendarProposal, CalendarTransport, CalendarWindow, CALENDAR_PROPOSE_OPERATION,
    CALENDAR_READ_OPERATION, MAX_BATCH_EVENTS, MAX_EVENTS, MAX_EVENT_DESCRIPTION_CHARS,
    MAX_EVENT_ID_CHARS, MAX_LOCATION_CHARS, MAX_TITLE_CHARS, MAX_WINDOW_DAYS,
};
use crate::email::{
    parse_ical_invites, CalendarInvite, EmailTransport, MAX_ADDRESS_CHARS, MAX_BODY_CHARS,
    MAX_KEYWORD_CHARS, MAX_RECIPIENTS, MAX_SUBJECT_CHARS,
};

/// Longest one wire line (IMAP or SMTP) accepted before the exchange is
/// declared off-bounds.
pub const MAX_LINE_BYTES: usize = 8_192;
/// Most untagged IMAP lines one command may produce.
pub const MAX_UNTAGGED_LINES: usize = 1_024;
/// Most reply lines one SMTP command may produce.
pub const MAX_SMTP_REPLY_LINES: usize = 64;
/// Longest one MIME header block (bytes).
pub const MAX_HEADER_BLOCK_BYTES: usize = 65_536;
/// Largest message this provider will append or submit (bytes).
pub const MAX_SMTP_MESSAGE_BYTES: usize = 1_048_576;
/// Largest one fetched calendar-data blob (bytes).
pub const MAX_ICS_EVENT_BYTES: usize = 262_144;
/// Longest an HTTP/WebDAV URL may be.
pub const MAX_URL_CHARS: usize = 2_048;
/// Longest a mail server host name may be.
pub const MAX_HOST_CHARS: usize = 255;
/// Longest an IMAP mailbox name may be.
pub const MAX_MAILBOX_CHARS: usize = 64;
/// Longest an ETag header value accepted for conditional PUT.
pub const MAX_ETAG_CHARS: usize = 256;
/// Longest a Message-ID header value accepted.
pub const MAX_MESSAGE_ID_CHARS: usize = 256;
/// Largest credential file accepted (bytes).
pub const MAX_CREDENTIAL_FILE_BYTES: u64 = 16_384;
/// Most UIDs one IMAP SEARCH may report.
pub const MAX_SEARCH_UIDS: usize = 1_000;
/// Most MIME parts scanned inside one message.
pub const MAX_MIME_PARTS: usize = 32;
/// Deepest MIME multipart nesting scanned.
pub const MAX_MIME_DEPTH: usize = 2;
/// Widest request deadline accepted, in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 120_000;
/// Widest response-byte ceiling accepted.
pub const MAX_RESPONSE_BYTES: u64 = 16_777_216;
/// Narrowest response-byte ceiling accepted.
pub const MIN_RESPONSE_BYTES: u64 = 1_024;

const MSG_BOUND: &str = "the request is outside the provider's declared bounds";
const MSG_LINE: &str = "the mail service sent a line beyond the declared bounds";
const MSG_CLOSED: &str = "the mail service closed the connection mid-exchange";
const MSG_IO: &str = "the mail connection failed an exchange step";
const MSG_IMAP_REJECTED: &str = "the mail service rejected the IMAP command";
const MSG_MAILBOX: &str = "the configured mailbox is not available on the mail service";
const MSG_UIDPLUS: &str = "the mail service did not return the stable UID assignment";
const MSG_TLS: &str = "the TLS session with the mail service could not be established";
const MSG_TLS_NAME: &str = "the configured mail host is not a valid TLS server name";
const MSG_UNEXPECTED_CONTINUATION: &str = "the mail service sent an unexpected continuation";
const MSG_STARTTLS: &str = "the SMTP service does not offer STARTTLS before authentication";
const MSG_NO_XOAUTH2: &str = "the SMTP service does not advertise XOAUTH2 authentication";
const MSG_NOT_AUTH: &str = "the SMTP session is not authenticated";
const MSG_SMTP_REJECTED: &str = "the SMTP service rejected the submission";
const MSG_MIME: &str = "the message MIME structure is not the supported shape";
const MSG_MIME_CHARSET: &str = "the message body charset is not supported";
const MSG_URL: &str = "the calendar URL is not a valid HTTP or HTTPS URL";
const MSG_URL_SCHEME: &str = "the calendar URL must be HTTP on loopback or HTTPS";
const MSG_URL_AUTHORITY: &str = "the calendar destination must stay on the configured service";
const MSG_REDIRECT: &str = "the calendar service attempted a redirect and redirects are disabled";
const MSG_HTTP: &str = "the calendar HTTP exchange failed";
const MSG_CALDAV_STATUS: &str = "the calendar service returned an unexpected status";
const MSG_NO_CALDAV: &str = "the provider configuration has no CalDAV endpoint";
const MSG_XML: &str = "the calendar multistatus response was not the expected shape";
const MSG_ICS: &str = "the calendar event iCalendar data is not the supported shape";
const MSG_ICS_TZ: &str = "the calendar event time is not a UTC iCalendar value";
const MSG_ICS_UID: &str = "the calendar event does not match the addressed UID";
const MSG_WINDOW: &str = "the calendar window is out of bounds";
const MSG_PROPOSAL: &str = "the calendar mutation arguments are out of bounds";
const MSG_CONFIG: &str = "the generic provider configuration is incomplete";
const MSG_CRED_SHAPE: &str = "the credential file is not the expected provider credential shape";
const MSG_CRED_MODE: &str = "the credential file is not private (mode 0600 required)";
const MSG_CRED_ACCOUNT: &str = "the credential file does not bind this account";
const MSG_CRED_WRITE: &str = "the credential bundle could not be updated";
const MSG_TENANT: &str = "the credential bundle tenant is not a valid OAuth tenant";
const MSG_CLIENT_ID: &str = "the credential bundle client id is not a valid OAuth client";
const MSG_REFRESH_SHAPE: &str = "the token service response was not the expected shape";
const MSG_NO_CALDAV_BASIC: &str = "the credential bundle carries no CalDAV Basic credential";

const MSG_EVENT_URL: &str = "the event id is not usable as a calendar resource path";
const MSG_FLAG_DELETED: &str = "the deleted flag is not a permitted management action";
const MSG_KEYWORD: &str = "a managed label is not a valid IMAP keyword";
const MSG_LEASE_DEPLOYMENT: &str =
    "the credential lease does not bind this deployment's configured credential";
const MSG_LEASE_REFUSED: &str =
    "the credential lease does not admit this operation for this account now";
const MSG_IN_DOUBT: &str =
    "the mutation may already have taken effect; the outcome is unknown and it must not be retried";

// ---------------------------------------------------------------------------
// Configuration (no defaults)
// ---------------------------------------------------------------------------

/// The TLS discipline of one mail endpoint. Both modes keep every
/// credential and message byte inside TLS: implicit TLS from the first
/// octet, STARTTLS before AUTH or any envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// TLS from the first octet (IMAP 993 style).
    ImplicitTls,
    /// Plaintext greeting, then an explicit STARTTLS upgrade (SMTP 587
    /// style). The upgrade is mandatory: without it the session is
    /// refused before authentication.
    StartTls,
}

/// One mail service endpoint: explicit host, explicit port, explicit
/// TLS mode.
#[derive(Clone, Debug)]
pub struct MailEndpoint {
    /// The service host name (used both for dialing and as the TLS
    /// server name).
    pub host: String,
    /// The service port.
    pub port: u16,
    /// The TLS discipline of this endpoint.
    pub tls: TlsMode,
}

/// The optional CalDAV deployment facts. `calendar_url` names the event
/// collection when it differs from `base_url`; when absent, `base_url`
/// is itself the collection the REPORT and PUT operations address.
#[derive(Clone, Debug)]
pub struct CaldavEndpoint {
    /// The CalDAV service root or collection URL.
    pub base_url: String,
    /// The event collection URL, when distinct from the base.
    pub calendar_url: Option<String>,
}

/// Every deployment fact of one generic provider account. No field has
/// a default; [`GenericProviderConfig::validated`] enforces the bounds.
#[derive(Clone)]
pub struct GenericProviderConfig {
    /// The account selector the governed surface addresses.
    pub account: String,
    /// The From address stamped onto drafts and the SMTP envelope.
    pub from_address: String,
    /// The IMAP service endpoint.
    pub imap: MailEndpoint,
    /// The SMTP submission endpoint.
    pub smtp: MailEndpoint,
    /// The EHLO client identity of this deployment.
    pub helo_name: String,
    /// The mailbox searched and read (typically the inbox).
    pub inbox_mailbox_id: String,
    /// The mailbox drafts are appended into.
    pub drafts_mailbox_id: String,
    /// The mailbox archived messages move into (deployment fact).
    pub archive_mailbox_id: String,
    /// The mailbox trashed messages move into (deployment fact).
    pub trash_mailbox_id: String,
    /// The optional CalDAV facts; without them calendar operations are
    /// typed refusals, never guesses.
    pub caldav: Option<CaldavEndpoint>,
    /// The scoped credential reference: opaque handle plus the
    /// sops-rendered 0600 credential file this backend resolves.
    pub credential: AccountSecretRef,
    /// Per-exchange deadline in milliseconds.
    pub request_timeout_ms: u64,
    /// Hard response-byte ceiling for HTTP exchanges and IMAP literals.
    pub max_response_bytes: u64,
}

impl std::fmt::Debug for GenericProviderConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenericProviderConfig")
            .field("account", &self.account)
            .field("from_address", &self.from_address)
            .field("imap", &self.imap)
            .field("smtp", &self.smtp)
            .field("helo_name", &self.helo_name)
            .field("inbox_mailbox_id", &self.inbox_mailbox_id)
            .field("drafts_mailbox_id", &self.drafts_mailbox_id)
            .field("archive_mailbox_id", &self.archive_mailbox_id)
            .field("trash_mailbox_id", &self.trash_mailbox_id)
            .field("caldav", &self.caldav)
            .field("credential", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl GenericProviderConfig {
    /// Validates and bounds every deployment fact. Returns the config
    /// unchanged in content; deadlines and byte ceilings are clamped to
    /// this module's ceilings the way the JMAP endpoint clamps them.
    pub fn validated(self) -> Result<Self, TransportFault> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(TransportFault::Protocol(MSG_CONFIG));
        }
        validate_address(&self.from_address)?;
        validate_endpoint(&self.imap)?;
        validate_endpoint(&self.smtp)?;
        if self.helo_name.trim().is_empty()
            || self.helo_name.len() > MAX_HOST_CHARS
            || !self.helo_name.bytes().all(is_hostname_byte)
        {
            return Err(TransportFault::Protocol(MSG_CONFIG));
        }
        for mailbox in [
            &self.inbox_mailbox_id,
            &self.drafts_mailbox_id,
            &self.archive_mailbox_id,
            &self.trash_mailbox_id,
        ] {
            validate_mailbox(mailbox)?;
        }
        if let Some(caldav) = &self.caldav {
            let base = validate_caldav_url(&caldav.base_url)?;
            if let Some(calendar_url) = &caldav.calendar_url {
                let calendar = validate_caldav_url(calendar_url)?;
                // The event collection may never live on another
                // origin than the base the credentials were chosen
                // for: same scheme, same host, same port, always.
                if calendar.origin() != base.origin() {
                    return Err(Protocol(MSG_URL_AUTHORITY));
                }
            }
        }
        let request_timeout_ms = self.request_timeout_ms.clamp(1, MAX_TIMEOUT_MS);
        let max_response_bytes = self
            .max_response_bytes
            .clamp(MIN_RESPONSE_BYTES, MAX_RESPONSE_BYTES);
        Ok(Self {
            account: self.account,
            from_address: self.from_address,
            imap: self.imap,
            smtp: self.smtp,
            helo_name: self.helo_name,
            inbox_mailbox_id: self.inbox_mailbox_id,
            drafts_mailbox_id: self.drafts_mailbox_id,
            archive_mailbox_id: self.archive_mailbox_id,
            trash_mailbox_id: self.trash_mailbox_id,
            caldav: self.caldav,
            credential: self.credential,
            request_timeout_ms,
            max_response_bytes,
        })
    }

    fn deadline(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// The event collection URL the REPORT and PUT operations address.
    /// The configured base and collection are re-bound same-origin at
    /// every use, so the credentials chosen for the base can never be
    /// sent to a foreign host.
    fn collection_url(&self) -> Result<String, TransportFault> {
        let caldav = self.caldav.as_ref().ok_or(Protocol(MSG_NO_CALDAV))?;
        let base = validate_caldav_url(&caldav.base_url)?;
        let collection = match &caldav.calendar_url {
            Some(calendar_url) => {
                let calendar = validate_caldav_url(calendar_url)?;
                if calendar.origin() != base.origin() {
                    return Err(Protocol(MSG_URL_AUTHORITY));
                }
                calendar
            }
            None => base,
        };
        Ok(collection.as_str().trim_end_matches('/').to_owned())
    }
}
use TransportFault::Protocol;

// ---------------------------------------------------------------------------
// Bounded validators
// ---------------------------------------------------------------------------

fn is_hostname_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')
}

fn has_no_controls(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// Normalizes one multiline text value (an email body or an event
/// description): CRLF pairs collapse to bare LFs, and no control
/// character other than the line feed survives. Header values,
/// identifiers, and commands stay strictly control-free via
/// [`has_no_controls`]; only bounded prose may be multiline.
fn normalized_multiline(value: &str) -> Option<String> {
    let normalized = value.replace("\r\n", "\n");
    if normalized.chars().any(|c| c.is_control() && c != '\n') {
        return None;
    }
    Some(normalized)
}

fn validate_endpoint(endpoint: &MailEndpoint) -> Result<(), TransportFault> {
    let host = endpoint.host.trim();
    if host.is_empty() || host.len() > MAX_HOST_CHARS || !host.bytes().all(is_hostname_byte) {
        return Err(Protocol(MSG_CONFIG));
    }
    if endpoint.port == 0 {
        return Err(Protocol(MSG_CONFIG));
    }
    Ok(())
}

/// Validates one email address: bounded, single `@`, no separators or
/// controls that could smuggle extra SMTP vertices or headers.
fn validate_address(address: &str) -> Result<(), TransportFault> {
    let address = address.trim();
    if address.is_empty() || address.len() > MAX_ADDRESS_CHARS || !has_no_controls(address) {
        return Err(Protocol(MSG_BOUND));
    }
    if address.matches('@').count() != 1 || address.contains([' ', ',', '<', '>', '"', '\\']) {
        return Err(Protocol(MSG_BOUND));
    }
    Ok(())
}

/// Validates one IMAP mailbox name against the safe quoted-string
/// subset this client emits: bounded, no controls, no characters that
/// require escaping.
fn validate_mailbox(mailbox: &str) -> Result<(), TransportFault> {
    if mailbox.is_empty() || mailbox.len() > MAX_MAILBOX_CHARS || !has_no_controls(mailbox) {
        return Err(Protocol(MSG_CONFIG));
    }
    if mailbox.contains(['"', '\\', '%', '*', ']']) {
        return Err(Protocol(MSG_CONFIG));
    }
    Ok(())
}

/// Validates one managed label: either an IMAP keyword atom or one of
/// the permitted system flags. `\Deleted` is refused by name — the
/// management surface must never be able to destroy content.
fn validate_keyword(keyword: &str) -> Result<(), TransportFault> {
    if keyword.is_empty() || keyword.len() > MAX_KEYWORD_CHARS || !has_no_controls(keyword) {
        return Err(Protocol(MSG_KEYWORD));
    }
    if let Some(flag) = keyword.strip_prefix('\\') {
        return match flag {
            "Seen" | "Flagged" | "Answered" | "Draft" => Ok(()),
            "Deleted" => Err(Protocol(MSG_FLAG_DELETED)),
            _ => Err(Protocol(MSG_KEYWORD)),
        };
    }
    if keyword.contains([' ', '(', ')', '{', '}', '"', '\\', '%', '*', '[', ']']) {
        return Err(Protocol(MSG_KEYWORD));
    }
    Ok(())
}

/// Validates one event id as a safe calendar resource path segment.
fn validate_event_id(event_id: &str) -> Result<(), TransportFault> {
    if event_id.is_empty() || event_id.len() > MAX_EVENT_ID_CHARS || !has_no_controls(event_id) {
        return Err(Protocol(MSG_EVENT_URL));
    }
    if event_id.contains(['/', '\\', '?', '#', '%', '"']) {
        return Err(Protocol(MSG_EVENT_URL));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CalDAV URL policy: loopback HTTP, remote HTTPS, no surprises
// ---------------------------------------------------------------------------

/// Requires HTTPS except on loopback; returns the parsed URL for authority checks.
pub fn validate_caldav_url(raw: &str) -> Result<url::Url, TransportFault> {
    if raw.is_empty() || raw.chars().count() > MAX_URL_CHARS {
        return Err(Protocol(MSG_URL));
    }
    let url = url::Url::parse(raw).map_err(|_| Protocol(MSG_URL))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" => {
            let loopback = match url.host_str() {
                Some("localhost") => true,
                Some(host) => host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false),
                None => false,
            };
            if loopback {
                Ok(url)
            } else {
                Err(Protocol(MSG_URL_SCHEME))
            }
        }
        _ => Err(Protocol(MSG_URL_SCHEME)),
    }
}

// ---------------------------------------------------------------------------
// Credential resolution: the 0600 scoped bundle
// ---------------------------------------------------------------------------

/// One resolved XOAUTH2 access token. It implements neither `Serialize`
/// nor `Display`, and its `Debug` redacts; the value is readable only
/// inside this module's framing code.
#[derive(Clone)]
pub struct AccessToken(String);

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

/// as [`AccessToken`].
#[derive(Clone)]
pub struct Password(String);

impl std::fmt::Debug for Password {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Password([REDACTED])")
    }
}

/// The resolved CalDAV Basic credential pair.
#[derive(Clone)]
pub struct BasicCredential {
    /// The Basic user name (an identifier, not a secret).
    pub user: String,
    /// The Basic password, redacted in every outward representation.
    pub password: Password,
}

impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BasicCredential")
            .field("user", &self.user)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// The credentials resolved from one account's scoped 0600 bundle.
#[derive(Clone)]
pub struct MailCredentials {
    /// The bound account (proved equal to the config and the lease).
    pub account: String,
    /// The SASL user framed into XOAUTH2.
    pub user: String,
    /// The XOAUTH2 bearer token.
    pub access_token: AccessToken,
    /// The optional Basic pair for the independently authenticated CalDAV service.
    pub caldav_basic: Option<BasicCredential>,
}

impl std::fmt::Debug for MailCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MailCredentials")
            .field("account", &self.account)
            .field("user", &self.user)
            .field("access_token", &"[REDACTED]")
            .field("caldav_basic", &self.caldav_basic)
            .finish()
    }
}

#[derive(serde::Deserialize)]
struct CredentialFile {
    version: u32,
    account: String,
    user: String,
    access_token: String,
    /// The refresh quartet is required: a bundle that cannot refresh
    /// is not a usable deployment fact, so it never parses here.
    expires_at: String,
    refresh_token: String,
    client_id: String,
    tenant: String,
    #[serde(default)]
    caldav_basic: Option<CaldavBasicFile>,
}

#[derive(serde::Deserialize)]
struct CaldavBasicFile {
    user: String,
    password: String,
}

/// Rechecks lease scope and credential handle before loading the account's private `0600` bundle.
/// Expiring tokens refresh once before dispatch, with an atomic private-file replacement.
fn resolve_mail_credentials(
    account: &str,
    credential: &AccountSecretRef,
    lease: &ScopedCredentialLease,
    operation: &'static str,
    now: time::OffsetDateTime,
    deadline: Duration,
) -> Result<MailCredentials, TransportFault> {
    let handle: OpaqueCredentialHandle = credential.handle().clone();
    if !lease.binds_handle(&handle) {
        return Err(TransportFault::Refused(MSG_LEASE_DEPLOYMENT));
    }
    if lease.admits(&capability(operation), account, now).is_err() {
        return Err(TransportFault::Refused(MSG_LEASE_REFUSED));
    }
    let mut file = load_credential_file(account, credential)?;
    maybe_refresh(&mut file, credential.secret_path(), now, deadline)?;
    let caldav_basic = file.caldav_basic.take().map(|basic| BasicCredential {
        user: basic.user,
        password: Password(basic.password),
    });
    Ok(MailCredentials {
        account: file.account,
        user: file.user,
        access_token: AccessToken(file.access_token),
        caldav_basic,
    })
}

/// The local half of the credential resolution, shared by every exchange
/// and by readiness: the sops-rendered file must exist, be a regular
/// private 0600 file within its byte bound, parse as the documented schema
/// (refresh quartet included), and bind the exact account. Reads only:
/// no lease, no refresh, no write.
fn load_credential_file(
    account: &str,
    credential: &AccountSecretRef,
) -> Result<CredentialFile, TransportFault> {
    let path = credential.secret_path();
    let metadata = std::fs::metadata(path)
        .map_err(|_| TransportFault::Unavailable(AccountUnavailable::Credentials))?;
    if !metadata.is_file() {
        return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(TransportFault::Refused(MSG_CRED_MODE));
        }
    }
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(Protocol(MSG_BOUND));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|_| TransportFault::Unavailable(AccountUnavailable::Credentials))?;
    let file: CredentialFile = serde_json::from_str(&raw).map_err(|_| Protocol(MSG_CRED_SHAPE))?;
    if file.version != 1 {
        return Err(Protocol(MSG_CRED_SHAPE));
    }
    if file.account != account {
        return Err(TransportFault::Refused(MSG_CRED_ACCOUNT));
    }
    if file.user.is_empty()
        || file.user.chars().count() > MAX_ADDRESS_CHARS
        || !has_no_controls(&file.user)
    {
        return Err(Protocol(MSG_CRED_SHAPE));
    }
    if file.access_token.is_empty()
        || file.access_token.len() > 8_192
        || file
            .access_token
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Protocol(MSG_CRED_SHAPE));
    }
    if file.refresh_token.is_empty()
        || file.refresh_token.len() > 4_096
        || !has_no_controls(&file.refresh_token)
    {
        return Err(Protocol(MSG_CRED_SHAPE));
    }
    if file.client_id.is_empty()
        || file.client_id.len() > 128
        || !file
            .client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Protocol(MSG_CLIENT_ID));
    }
    if file.tenant.is_empty()
        || file.tenant.len() > 128
        || !file
            .tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(Protocol(MSG_TENANT));
    }
    if time::OffsetDateTime::parse(
        file.expires_at.trim(),
        &time::format_description::well_known::Rfc3339,
    )
    .is_err()
    {
        return Err(Protocol(MSG_CRED_SHAPE));
    }
    if file.caldav_basic.as_ref().is_some_and(|basic| {
        basic.user.is_empty() || basic.password.is_empty() || !has_no_controls(&basic.user)
    }) {
        return Err(Protocol(MSG_CRED_SHAPE));
    }
    Ok(file)
}

/// Seconds before expiry at which a token counts as expiring.
const REFRESH_MARGIN_SECONDS: i64 = 60;
/// Hard response-byte ceiling for one token-endpoint exchange.
const MAX_TOKEN_RESPONSE_BYTES: u64 = 65_536;
/// Widest `expires_in` one token response may declare, in seconds.
const MAX_EXPIRES_IN_SECONDS: i64 = 86_400;
/// Serializes every refresh in this process: two concurrent exchanges
/// must never both refresh and clobber each other's rotated grant.
static REFRESH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether the bundle's access token is still good beyond the refresh
/// margin.
fn bundle_is_fresh(file: &CredentialFile, now: time::OffsetDateTime) -> bool {
    time::OffsetDateTime::parse(
        file.expires_at.trim(),
        &time::format_description::well_known::Rfc3339,
    )
    .ok()
    .map(|expires| now < expires - time::Duration::seconds(REFRESH_MARGIN_SECONDS))
    .unwrap_or(false)
}

/// Refreshes the bundle's access token when it is expiring within the
/// margin, under the process-wide refresh lock: one `refresh_token`
/// grant POST against the tenant v2 token endpoint (HTTPS, redirects
/// off, bounded response, no retry), the rotated refresh token
/// preserved when the service returns one, and an exclusive-create
/// atomic rewrite of the same 0600 file. The bundle is re-read under
/// the lock first: a concurrent refresher may already have rotated the
/// grant, and the freshest durable state wins.
fn maybe_refresh(
    file: &mut CredentialFile,
    path: &std::path::Path,
    now: time::OffsetDateTime,
    deadline: Duration,
) -> Result<(), TransportFault> {
    let _lock = REFRESH_LOCK.lock().map_err(|_| Protocol(MSG_CRED_WRITE))?;
    if let Ok(raw) = std::fs::read_to_string(path) {
        if raw.len() as u64 <= MAX_CREDENTIAL_FILE_BYTES {
            if let Ok(fresh) = serde_json::from_str::<CredentialFile>(&raw) {
                // Only the bundle this resolution already validated —
                // same account, same version — may replace it.
                if fresh.account == file.account && fresh.version == 1 {
                    let fresh_is_good = bundle_is_fresh(&fresh, now);
                    *file = fresh;
                    if fresh_is_good {
                        return Ok(());
                    }
                }
            }
        }
    }
    if bundle_is_fresh(file, now) {
        return Ok(());
    }
    let endpoint = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        file.tenant
    );
    let url = validate_caldav_url(&endpoint)?;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &file.client_id)
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", &file.refresh_token)
        .finish();
    let client = crate::http_pool::no_redirect().map_err(|_| Protocol(MSG_HTTP))?;
    let response = client
        .post(url)
        .timeout(deadline)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form)
        .send()
        .map_err(map_http_error)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
    }
    let mut bytes = Vec::new();
    let mut reader = response.take(MAX_TOKEN_RESPONSE_BYTES.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| Protocol(MSG_HTTP))?;
    if bytes.len() as u64 > MAX_TOKEN_RESPONSE_BYTES {
        return Err(Protocol(MSG_BOUND));
    }
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Protocol(MSG_REFRESH_SHAPE))?;
    let access_token = document
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| {
            !token.is_empty()
                && token.len() <= 8_192
                && !token.chars().any(|c| c.is_control() || c.is_whitespace())
        })
        .ok_or(Protocol(MSG_REFRESH_SHAPE))?;
    let expires_in = document
        .get("expires_in")
        .and_then(serde_json::Value::as_i64)
        .filter(|seconds| *seconds > 0 && *seconds <= MAX_EXPIRES_IN_SECONDS)
        .ok_or(Protocol(MSG_REFRESH_SHAPE))?;
    if let Some(rotated) = document
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty() && token.len() <= 4_096 && has_no_controls(token))
    {
        file.refresh_token = rotated.to_owned();
    }
    file.access_token = access_token.to_owned();
    file.expires_at = rfc3339_utc(now + time::Duration::seconds(expires_in))?;
    rewrite_credential_file(path, file)
}

/// Escapes one string as a JSON string body (no control bytes ever
/// reach the file raw).
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => out.push_str(&format!("\\u{:04x}", other as u32)),
            other => out.push(other),
        }
    }
    out
}

/// Atomically rewrites the credential bundle: exclusive-create
/// uniquely named temporary sibling at mode 0600, fsync, rename over
/// the original, fsync of the directory so the rename itself is
/// durable. A failed attempt removes its temporary sibling; no litter
/// is ever left beside the live bundle.
fn rewrite_credential_file(
    path: &std::path::Path,
    file: &CredentialFile,
) -> Result<(), TransportFault> {
    let mut sections = vec![
        format!("\"version\":{}", file.version),
        format!("\"account\":\"{}\"", json_escape(&file.account)),
        format!("\"user\":\"{}\"", json_escape(&file.user)),
        format!("\"access_token\":\"{}\"", json_escape(&file.access_token)),
        format!("\"expires_at\":\"{}\"", json_escape(&file.expires_at)),
        format!("\"refresh_token\":\"{}\"", json_escape(&file.refresh_token)),
        format!("\"client_id\":\"{}\"", json_escape(&file.client_id)),
        format!("\"tenant\":\"{}\"", json_escape(&file.tenant)),
    ];
    if let Some(caldav_basic) = &file.caldav_basic {
        sections.push(format!(
            "\"caldav_basic\":{{\"user\":\"{}\",\"password\":\"{}\"}}",
            json_escape(&caldav_basic.user),
            json_escape(&caldav_basic.password)
        ));
    }
    let body = format!("{{{}}}\n", sections.join(","));
    let directory = path.parent().ok_or(Protocol(MSG_CRED_WRITE))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("credential");
    let temporary = directory.join(format!(".{name}.{}", uuid::Uuid::new_v4()));
    let written = (|| -> Result<(), TransportFault> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut handle = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| Protocol(MSG_CRED_WRITE))?;
            handle
                .write_all(body.as_bytes())
                .map_err(|_| Protocol(MSG_CRED_WRITE))?;
            handle.sync_all().map_err(|_| Protocol(MSG_CRED_WRITE))?;
        }
        #[cfg(not(unix))]
        {
            let mut handle = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_| Protocol(MSG_CRED_WRITE))?;
            handle
                .write_all(body.as_bytes())
                .map_err(|_| Protocol(MSG_CRED_WRITE))?;
            handle.sync_all().map_err(|_| Protocol(MSG_CRED_WRITE))?;
        }
        std::fs::rename(&temporary, path).map_err(|_| Protocol(MSG_CRED_WRITE))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written?;
    std::fs::File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| Protocol(MSG_CRED_WRITE))?;
    Ok(())
}

/// Builds the SASL XOAUTH2 client first response (RFC 7628 framing):
/// `user=<user>\x01auth=Bearer <token>\x01\x01`, base64-encoded. The
/// token never appears outside the encoded frame.
fn xoauth2_client_response(user: &str, token: &AccessToken) -> String {
    let plain = format!("user={user}\u{1}auth=Bearer {}\u{1}\u{1}", token.0);
    BASE64_STD.encode(plain)
}

// ---------------------------------------------------------------------------
// Lease enforcement
// ---------------------------------------------------------------------------

/// Builds the capability id of one of this module's reserved registry
/// constants. The ids are fixed upstream and known to satisfy the
/// registry grammar.
fn capability(id: &'static str) -> CapabilityId {
    CapabilityId::new(id).expect("the reserved registry capability id is valid")
}

// ---------------------------------------------------------------------------
// Time helpers (bounded, deterministic)
// ---------------------------------------------------------------------------

fn basic_utc_format() -> Vec<time::format_description::FormatItem<'static>> {
    time::format_description::parse_borrowed::<1>("[year][month][day]T[hour][minute][second]Z")
        .expect("the static basic-UTC format description is valid")
}

/// Rejects sub-second calendar timestamps.
fn parse_rfc3339_whole(value: &str) -> Result<time::OffsetDateTime, TransportFault> {
    let value = value.trim();
    let parsed = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| Protocol(MSG_PROPOSAL))?;
    if parsed.nanosecond() != 0 {
        return Err(Protocol(MSG_PROPOSAL));
    }
    Ok(parsed)
}

/// Renders an instant in the iCalendar basic UTC format
/// (`YYYYMMDDTHHMMSSZ`).
fn ics_utc(instant: time::OffsetDateTime) -> Result<String, TransportFault> {
    let format = basic_utc_format();
    instant
        .to_utc()
        .format(&format)
        .map_err(|_| Protocol(MSG_PROPOSAL))
}

/// Parses an iCalendar UTC date-time (`YYYYMMDDTHHMMSSZ`) or all-day
/// date (`YYYYMMDD`, midnight UTC) into an RFC 3339 instant.
fn ics_to_rfc3339(value: &str) -> Result<time::OffsetDateTime, TransportFault> {
    let value = value.trim();
    if let Ok(instant) = time::PrimitiveDateTime::parse(value, &basic_utc_format()) {
        return Ok(instant.assume_utc());
    }
    let date_format = time::format_description::parse_borrowed::<1>("[year][month][day]")
        .expect("the static date format description is valid");
    let date = time::Date::parse(value, &date_format).map_err(|_| Protocol(MSG_ICS))?;
    Ok(date.midnight().assume_utc())
}

/// Renders an instant as RFC 3339 UTC.
fn rfc3339_utc(instant: time::OffsetDateTime) -> Result<String, TransportFault> {
    instant
        .to_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| Protocol(MSG_PROPOSAL))
}

const IMAP_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parses an IMAP INTERNALDATE value
/// (`"27-Sep-2026 12:00:00 +0000"`) into an instant.
fn parse_imap_date(value: &str) -> Result<time::OffsetDateTime, TransportFault> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [day_month_year, clock, offset] = parts.as_slice() else {
        return Err(Protocol(MSG_MIME));
    };
    let mut pieces = day_month_year.split('-');
    let day = pieces
        .next()
        .and_then(|d| d.parse::<u8>().ok())
        .filter(|d| (1..=31).contains(d))
        .ok_or(Protocol(MSG_MIME))?;
    let month = pieces
        .next()
        .and_then(|m| IMAP_MONTHS.iter().position(|name| *name == m))
        .ok_or(Protocol(MSG_MIME))?;
    let month = time::Month::try_from(month as u8 + 1).map_err(|_| Protocol(MSG_MIME))?;
    let year = pieces
        .next()
        .and_then(|y| y.parse::<i32>().ok())
        .ok_or(Protocol(MSG_MIME))?;
    let mut clock = clock.split(':');
    let hour = clock.next().and_then(|v| v.parse::<u8>().ok());
    let minute = clock.next().and_then(|v| v.parse::<u8>().ok());
    let second = clock.next().and_then(|v| v.parse::<u8>().ok());
    let (hour, minute, second) = match (hour, minute, second) {
        (Some(h), Some(m), Some(s)) if h < 24 && m < 60 && s < 60 => (h, m, s),
        _ => return Err(Protocol(MSG_MIME)),
    };
    let offset = parse_utc_offset(offset).ok_or(Protocol(MSG_MIME))?;
    let date = time::Date::from_calendar_date(year, month, day).map_err(|_| Protocol(MSG_MIME))?;
    let time_value = time::Time::from_hms(hour, minute, second).map_err(|_| Protocol(MSG_MIME))?;
    Ok(time::PrimitiveDateTime::new(date, time_value).assume_offset(offset))
}

fn parse_utc_offset(value: &str) -> Option<time::UtcOffset> {
    let bytes = value.as_bytes();
    if bytes.len() != 5 || (bytes[0] != b'+' && bytes[0] != b'-') {
        return None;
    }
    let hours: i8 = value.get(1..3)?.parse().ok()?;
    let minutes: i8 = value.get(3..5)?.parse().ok()?;
    let seconds = i32::from(hours) * 3600 + i32::from(minutes) * 60;
    time::UtcOffset::from_whole_seconds(if bytes[0] == b'-' { -seconds } else { seconds }).ok()
}

/// Renders an instant as an RFC 5322 date-time (`Date:` header).
fn rfc5322_date(instant: time::OffsetDateTime) -> Result<String, TransportFault> {
    let format = time::format_description::parse_borrowed::<1>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] +0000",
    )
    .expect("the static RFC 5322 format description is valid");
    instant
        .to_utc()
        .format(&format)
        .map_err(|_| Protocol(MSG_BOUND))
}

// ---------------------------------------------------------------------------
// Wire transport: bounded TLS'd streams
// ---------------------------------------------------------------------------

/// One established mail connection: plaintext (only ever inside a test
/// seam or the pre-STARTTLS handshake window) or TLS.
enum MailStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for MailStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for MailStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}
fn io_fault(error: &std::io::Error) -> TransportFault {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => TransportFault::Timeout,
        std::io::ErrorKind::ConnectionRefused => {
            TransportFault::Unavailable(AccountUnavailable::Service)
        }
        std::io::ErrorKind::UnexpectedEof => Protocol(MSG_CLOSED),
        _ => Protocol(MSG_IO),
    }
}

fn tcp_connect(host: &str, port: u16, deadline: Duration) -> Result<TcpStream, TransportFault> {
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|_| Protocol(MSG_IO))?
        .next()
        .ok_or(Protocol(MSG_IO))?;
    // The dial itself is inside the exchange deadline: an unreachable
    // service can never hold a mutation past its bound.
    let stream =
        TcpStream::connect_timeout(&address, deadline).map_err(|error| match error.kind() {
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut => {
                TransportFault::Unavailable(AccountUnavailable::Service)
            }
            _ => Protocol(MSG_IO),
        })?;
    stream
        .set_read_timeout(Some(deadline))
        .map_err(|_| Protocol(MSG_IO))?;
    stream
        .set_write_timeout(Some(deadline))
        .map_err(|_| Protocol(MSG_IO))?;
    Ok(stream)
}

fn tls_client(
    host: &str,
    tcp: TcpStream,
    deadline: Duration,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, TransportFault> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| Protocol(MSG_TLS_NAME))?;
    let connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|_| Protocol(MSG_TLS))?;
    let stream = rustls::StreamOwned::new(connection, tcp);
    stream
        .get_ref()
        .set_read_timeout(Some(deadline))
        .map_err(|_| Protocol(MSG_IO))?;
    stream
        .get_ref()
        .set_write_timeout(Some(deadline))
        .map_err(|_| Protocol(MSG_IO))?;
    Ok(stream)
}

/// Reads one CRLF-terminated line under the hard byte bound. The line
/// terminator is stripped; upstream text never enters any fault.
fn read_line_bounded(stream: &mut MailStream, max: usize) -> Result<String, TransportFault> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).map_err(|error| io_fault(&error))?;
        if read == 0 {
            return Err(Protocol(MSG_CLOSED));
        }
        if byte[0] == b'\n' {
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return String::from_utf8(buf).map_err(|_| Protocol(MSG_LINE));
        }
        buf.push(byte[0]);
        if buf.len() > max {
            return Err(Protocol(MSG_LINE));
        }
    }
}

fn write_all(stream: &mut MailStream, bytes: &[u8]) -> Result<(), TransportFault> {
    stream.write_all(bytes).map_err(|error| io_fault(&error))?;
    stream.flush().map_err(|error| io_fault(&error))
}

fn quoted_mailbox(mailbox: &str) -> String {
    format!("\"{mailbox}\"")
}

// ---------------------------------------------------------------------------
// IMAP session
// ---------------------------------------------------------------------------

/// One parsed IMAP header response: UID, optional received instant, and header bytes.
pub type ImapHeader = (u32, Option<String>, Vec<u8>);

/// One parsed full IMAP message: raw message bytes and optional received instant.
pub type ImapMessage = (Vec<u8>, Option<String>);

/// One untagged IMAP response line plus any literals it carried.
struct UntaggedLine {
    line: String,
    literals: Vec<Vec<u8>>,
}

/// One authenticated-capable IMAP session over an established stream.
/// All commands use UID forms; nothing here can expunge, delete, or
/// unsubscribe.
pub struct ImapSession {
    stream: MailStream,
    tag: u32,
    literal_bound: u64,
    /// The whole-exchange deadline every read is armed against.
    deadline: Duration,
    /// When this session was established; the deadline is measured
    /// from here, so a dribbling server cannot extend the exchange.
    started: Instant,
    /// Cumulative response bytes spent by the exchange in flight,
    /// lines and literals together, against `literal_bound`.
    spent: u64,
}

impl ImapSession {
    /// Production entry: dials the configured endpoint, enforces the
    /// endpoint's TLS discipline (implicit TLS, or STARTTLS upgrade
    /// before any other exchange), and consumes the greeting.
    pub fn connect(
        endpoint: &MailEndpoint,
        deadline: Duration,
        literal_bound: u64,
    ) -> Result<Self, TransportFault> {
        let tcp = tcp_connect(&endpoint.host, endpoint.port, deadline)?;
        match endpoint.tls {
            TlsMode::ImplicitTls => {
                let tls = tls_client(&endpoint.host, tcp, deadline)?;
                let mut session = Self {
                    stream: MailStream::Tls(Box::new(tls)),
                    tag: 0,
                    literal_bound,
                    deadline,
                    started: Instant::now(),
                    spent: 0,
                };
                session.read_greeting()?;
                Ok(session)
            }
            TlsMode::StartTls => {
                let mut session = Self {
                    stream: MailStream::Plain(tcp),
                    tag: 0,
                    literal_bound,
                    deadline,
                    started: Instant::now(),
                    spent: 0,
                };
                session.read_greeting()?;
                session.starttls(&endpoint.host, deadline)?;
                Ok(session)
            }
        }
    }

    /// Scripted-test seam: wraps an already-connected plaintext loopback
    /// stream and consumes the greeting the script has written. The
    /// production path is [`ImapSession::connect`], which always
    /// enforces TLS.
    pub fn over_insecure_stream(
        stream: TcpStream,
        literal_bound: u64,
    ) -> Result<Self, TransportFault> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| Protocol(MSG_IO))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| Protocol(MSG_IO))?;
        let mut session = Self {
            stream: MailStream::Plain(stream),
            tag: 0,
            literal_bound,
            deadline: Duration::from_secs(10),
            started: Instant::now(),
            spent: 0,
        };
        session.read_greeting()?;
        Ok(session)
    }

    fn read_greeting(&mut self) -> Result<(), TransportFault> {
        let line = self.read_physical_line()?;
        let status = line.split(' ').nth(1);
        if matches!(status, Some("OK") | Some("PREAUTH")) {
            Ok(())
        } else {
            Err(Protocol(MSG_IMAP_REJECTED))
        }
    }

    fn starttls(&mut self, host: &str, deadline: Duration) -> Result<(), TransportFault> {
        self.tag += 1;
        let tag = format!("A{:03}", self.tag);
        write_all(&mut self.stream, format!("{tag} STARTTLS\r\n").as_bytes())?;
        let reply = self.read_tagged(&tag)?;
        if !reply.0 {
            return Err(Protocol(MSG_STARTTLS));
        }
        let plain = match &mut self.stream {
            MailStream::Plain(tcp) => tcp.try_clone().map_err(|_| Protocol(MSG_TLS))?,
            MailStream::Tls(_) => return Err(Protocol(MSG_TLS)),
        };
        let tls = tls_client(host, plain, deadline)?;
        self.stream = MailStream::Tls(Box::new(tls));
        Ok(())
    }

    /// Arms the remaining exchange deadline against the socket: every
    /// subsequent read or write may take at most the time that is
    /// still left, so no server can dribble one exchange past its
    /// bound.
    fn arm_deadline(&mut self) -> Result<(), TransportFault> {
        let Some(remaining) = self.deadline.checked_sub(self.started.elapsed()) else {
            return Err(TransportFault::Timeout);
        };
        let socket = match &mut self.stream {
            MailStream::Plain(tcp) => tcp,
            MailStream::Tls(tls) => tls.get_mut(),
        };
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| Protocol(MSG_IO))?;
        socket
            .set_write_timeout(Some(remaining))
            .map_err(|_| Protocol(MSG_IO))?;
        Ok(())
    }

    /// Reads one physical CRLF line under the byte bound, charging it
    /// to the exchange's cumulative response budget.
    fn read_physical_line(&mut self) -> Result<String, TransportFault> {
        self.arm_deadline()?;
        let line = read_line_bounded(&mut self.stream, MAX_LINE_BYTES)?;
        self.spent += line.len() as u64;
        if self.spent > self.literal_bound {
            return Err(Protocol(MSG_BOUND));
        }
        Ok(line)
    }

    /// Reads one logical response line, consuming any `{N}` literals
    /// the line advertises. This is the standard RFC 3501 framing: a
    /// line ending in `{N}` announces N literal bytes that follow,
    /// whatever part of the response they belong to, and the response
    /// continues on the line after them.
    fn read_line_with_literals(&mut self) -> Result<(String, Vec<Vec<u8>>), TransportFault> {
        let mut literals = Vec::new();
        let mut text = self.read_physical_line()?;
        loop {
            let Some(open) = text.rfind('{') else {
                return Ok((text, literals));
            };
            if !text.ends_with('}') {
                return Ok((text, literals));
            }
            let Ok(size) = text[open + 1..text.len() - 1].parse::<usize>() else {
                // A brace run that is not a literal announcement is
                // ordinary response text, never an abort.
                return Ok((text, literals));
            };
            self.spent += size as u64;
            if size == 0 || self.spent > self.literal_bound {
                return Err(Protocol(MSG_BOUND));
            }
            self.arm_deadline()?;
            let mut bytes = vec![0u8; size];
            self.stream
                .read_exact(&mut bytes)
                .map_err(|error| io_fault(&error))?;
            literals.push(bytes);
            text.push_str(&self.read_physical_line()?);
        }
    }

    /// Reads one tagged reply for `tag`, collecting bounded untagged
    /// lines on the way. Returns (ok, tagged line).
    fn read_tagged(&mut self, tag: &str) -> Result<(bool, String), TransportFault> {
        let prefix = format!("{tag} ");
        let mut untagged = 0usize;
        loop {
            let (line, _) = self.read_line_with_literals()?;
            if line.starts_with("* ") {
                untagged += 1;
                if untagged > MAX_UNTAGGED_LINES {
                    return Err(Protocol(MSG_BOUND));
                }
                continue;
            }
            if line.starts_with("+ ") {
                return Err(Protocol(MSG_UNEXPECTED_CONTINUATION));
            }
            if line.starts_with(&prefix) {
                let status = line[prefix.len()..].split(' ').next().unwrap_or("");
                return match status {
                    "OK" => Ok((true, line)),
                    "NO" | "BAD" => Ok((false, line)),
                    _ => Err(Protocol(MSG_IMAP_REJECTED)),
                };
            }
        }
    }

    /// Sends one simple command (no literal) and collects its untagged
    /// replies.
    fn command(&mut self, text: &str) -> Result<Vec<UntaggedLine>, TransportFault> {
        self.tag += 1;
        self.spent = 0;
        let tag = format!("A{:03}", self.tag);
        write_all(&mut self.stream, format!("{tag} {text}\r\n").as_bytes())?;
        let prefix = format!("{tag} ");
        let mut untagged = Vec::new();
        loop {
            let (line, literals) = self.read_line_with_literals()?;
            if let Some(stripped) = line.strip_prefix("* ") {
                untagged.push(UntaggedLine {
                    line: stripped.to_owned(),
                    literals,
                });
                if untagged.len() > MAX_UNTAGGED_LINES {
                    return Err(Protocol(MSG_BOUND));
                }
                continue;
            }
            if line.starts_with("+ ") {
                return Err(Protocol(MSG_UNEXPECTED_CONTINUATION));
            }
            if line.starts_with(&prefix) {
                let status = line[prefix.len()..].split(' ').next().unwrap_or("");
                if status == "OK" {
                    return Ok(untagged);
                }
                return Err(Protocol(MSG_IMAP_REJECTED));
            }
        }
    }

    /// Authenticates with SASL XOAUTH2 over SASL-IR. A server error
    /// continuation is drained (the empty client continuation) and the
    /// exchange reports typed credential unavailability; the challenge
    /// text is never surfaced.
    pub fn authenticate_xoauth2(
        &mut self,
        credentials: &MailCredentials,
    ) -> Result<(), TransportFault> {
        let payload = xoauth2_client_response(&credentials.user, &credentials.access_token);
        self.tag += 1;
        let tag = format!("A{:03}", self.tag);
        write_all(
            &mut self.stream,
            format!("{tag} AUTHENTICATE XOAUTH2 {payload}\r\n").as_bytes(),
        )?;
        loop {
            let (line, _) = self.read_line_with_literals()?;
            if line.starts_with("* ") {
                continue;
            }
            if line.starts_with("+ ") {
                // The server rejected the token and offered an error
                // continuation: answer it, then read the tagged
                // failure. The challenge text is never surfaced.
                write_all(&mut self.stream, b"\r\n")?;
                let _ = self.read_tagged(&tag)?;
                return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
            }
            let prefix = format!("{tag} ");
            let status = line
                .strip_prefix(&prefix)
                .unwrap_or("")
                .split(' ')
                .next()
                .unwrap_or("");
            if status == "OK" {
                return Ok(());
            }
            return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
        }
    }

    /// Selects a mailbox for UID operations. A server NO is the
    /// configured mailbox being unavailable; every other failure
    /// keeps its own typing.
    pub fn select_mailbox(&mut self, mailbox: &str) -> Result<(), TransportFault> {
        match self.command(&format!("SELECT {}", quoted_mailbox(mailbox))) {
            Ok(_) => Ok(()),
            Err(TransportFault::Protocol(MSG_IMAP_REJECTED)) => Err(Protocol(MSG_MAILBOX)),
            Err(other) => Err(other),
        }
    }
    /// `UID SEARCH TEXT`: returns the matching UIDs in ascending
    /// server order, bounded.
    pub fn uid_search(&mut self, text: &str) -> Result<Vec<u32>, TransportFault> {
        self.tag += 1;
        self.spent = 0;
        let tag = format!("A{:03}", self.tag);
        let bytes = text.as_bytes();
        write_all(
            &mut self.stream,
            format!("{tag} UID SEARCH TEXT {{{}}}\r\n", bytes.len()).as_bytes(),
        )?;
        let (line, _) = self.read_line_with_literals()?;
        if !line.starts_with("+ ") {
            return Err(Protocol(MSG_IMAP_REJECTED));
        }
        self.spent += bytes.len() as u64;
        write_all(&mut self.stream, bytes)?;
        write_all(&mut self.stream, b"\r\n")?;
        let mut uids = Vec::new();
        let prefix = format!("{tag} ");
        loop {
            let (line, _) = self.read_line_with_literals()?;
            if let Some(rest) = line.strip_prefix("* SEARCH") {
                for token in rest.split_whitespace() {
                    let uid = token.parse::<u32>().map_err(|_| Protocol(MSG_LINE))?;
                    uids.push(uid);
                    if uids.len() > MAX_SEARCH_UIDS {
                        return Err(Protocol(MSG_BOUND));
                    }
                }
                continue;
            }
            if line.starts_with(&prefix) {
                let status = line[prefix.len()..].split(' ').next().unwrap_or("");
                if status == "OK" {
                    return Ok(uids);
                }
                return Err(Protocol(MSG_IMAP_REJECTED));
            }
        }
    }

    /// `UID FETCH` of the bounded header fields plus INTERNALDATE for
    /// one UID set. Returns (uid, internaldate, header bytes) triples.
    pub fn uid_fetch_headers(&mut self, uids: &[u32]) -> Result<Vec<ImapHeader>, TransportFault> {
        let set = uids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let untagged = self.command(&format!(
            "UID FETCH {set} (UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])"
        ))?;
        let mut found = Vec::new();
        for line in untagged {
            // Standard untagged framing: `* <seq> FETCH (...)`, so the
            // payload is addressed by its sequence-number FETCH marker,
            // never by a leading `FETCH `.
            let Some((_, payload)) = fetch_payload(&line.line) else {
                continue;
            };
            let uid = extract_number(payload, "UID ").ok_or(Protocol(MSG_LINE))?;
            let date = extract_quoted(&line.line, "INTERNALDATE ")
                .and_then(|raw| parse_imap_date(&raw).ok());
            let date = match date {
                Some(instant) => Some(rfc3339_utc(instant)?),
                None => None,
            };
            let headers = line.literals.into_iter().next().unwrap_or_default();
            found.push((uid, date, headers));
        }
        Ok(found)
    }

    /// `UID FETCH` of one full message. Returns None when the UID has
    /// no message (an honest absence, never a guess).
    pub fn uid_fetch_full(&mut self, uid: u32) -> Result<Option<ImapMessage>, TransportFault> {
        let untagged = self.command(&format!("UID FETCH {uid} (UID INTERNALDATE BODY.PEEK[])"))?;
        for line in untagged {
            let Some((_, payload)) = fetch_payload(&line.line) else {
                continue;
            };
            let found = extract_number(payload, "UID ").ok_or(Protocol(MSG_LINE))?;
            if found != uid {
                return Err(Protocol(MSG_BOUND));
            }
            let received_at = match extract_quoted(&line.line, "INTERNALDATE ")
                .and_then(|raw| parse_imap_date(&raw).ok())
            {
                Some(instant) => Some(rfc3339_utc(instant)?),
                None => None,
            };
            let bytes = line.literals.into_iter().next().unwrap_or_default();
            return Ok(Some((bytes, received_at)));
        }
        Ok(None)
    }

    /// `UID APPEND` with a literal payload; returns the stable UID the
    /// server assigned (UIDPLUS APPENDUID) — never a fabricated id.
    pub fn uid_append(
        &mut self,
        mailbox: &str,
        flags: &str,
        message: &[u8],
    ) -> Result<u32, TransportFault> {
        if message.len() as u64 > self.literal_bound || message.len() > MAX_SMTP_MESSAGE_BYTES {
            return Err(Protocol(MSG_BOUND));
        }
        self.tag += 1;
        self.spent = 0;
        let tag = format!("A{:03}", self.tag);
        write_all(
            &mut self.stream,
            format!(
                "{tag} APPEND {} ({}) {{{}}}\r\n",
                quoted_mailbox(mailbox),
                flags,
                message.len()
            )
            .as_bytes(),
        )?;
        let (line, _) = self.read_line_with_literals()?;
        if !line.starts_with("+ ") {
            return Err(Protocol(MSG_IMAP_REJECTED));
        }
        // From here the append is committed: the message bytes are on
        // the wire, so any fault reading the outcome is in-doubt and
        // must never look like a clean retryable failure.
        self.spent += message.len() as u64;
        write_all(&mut self.stream, message)?;
        write_all(&mut self.stream, b"\r\n")?;
        let (ok, tagged) = self.read_tagged(&tag).map_err(in_doubt_fault)?;
        if !ok {
            return Err(Protocol(MSG_IMAP_REJECTED));
        }
        extract_append_uid(&tagged).ok_or(Protocol(MSG_UIDPLUS))
    }

    /// `UID STORE` with a silent flag patch (add or remove). Only
    /// validated keywords reach the wire.
    pub fn uid_store(
        &mut self,
        uid: u32,
        add: bool,
        keywords: &[String],
    ) -> Result<(), TransportFault> {
        if keywords.is_empty() {
            return Ok(());
        }
        let operation = if add {
            "+FLAGS.SILENT"
        } else {
            "-FLAGS.SILENT"
        };
        let list = keywords.join(" ");
        self.command(&format!("UID STORE {uid} {operation} ({list})"))?;
        Ok(())
    }

    /// `UID MOVE` into one configured mailbox (RFC 6851). The message
    /// persists in the destination; nothing is destroyed. Returns the
    /// destination UID from the UIDPLUS COPYUID response.
    pub fn uid_move(&mut self, uid: u32, mailbox: &str) -> Result<u32, TransportFault> {
        self.tag += 1;
        let tag = format!("A{:03}", self.tag);
        write_all(
            &mut self.stream,
            format!("{tag} UID MOVE {uid} {}\r\n", quoted_mailbox(mailbox)).as_bytes(),
        )?;
        let (ok, tagged) = self.read_tagged(&tag)?;
        if !ok {
            return Err(Protocol(MSG_IMAP_REJECTED));
        }
        extract_move_uid(&tagged).ok_or(Protocol(MSG_UIDPLUS))
    }

    /// Best-effort LOGOUT; failures are ignored (the socket closes
    /// anyway) and never surface.
    pub fn logout(&mut self) {
        self.tag += 1;
        let tag = format!("A{:03}", self.tag);
        let _ = write_all(&mut self.stream, format!("{tag} LOGOUT\r\n").as_bytes());
    }
}

/// Splits one untagged `* <seq> FETCH ...` line (with the `* `
/// already stripped by the command loop) into its sequence number and
/// response payload, or `None` for any other untagged line.
fn fetch_payload(line: &str) -> Option<(&str, &str)> {
    let (sequence, rest) = line.split_once(' ')?;
    let rest = rest.strip_prefix("FETCH ")?;
    if sequence.is_empty() || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((sequence, rest))
}

/// Extracts the first number after a fixed marker in an IMAP response
/// line.
fn extract_number(line: &str, marker: &str) -> Option<u32> {
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Extracts a quoted value after a fixed marker.
fn extract_quoted(line: &str, marker: &str) -> Option<String> {
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Classifies a fault raised after a step may already have taken
/// effect: refusals and URL-policy decisions happen before any byte
/// reaches the service, so they keep their typing; everything else is
/// in-doubt — the outcome is unknowable and the step is never retried.
fn in_doubt_fault(fault: TransportFault) -> TransportFault {
    match fault {
        TransportFault::Refused(_) => fault,
        TransportFault::Protocol(MSG_URL | MSG_URL_SCHEME | MSG_URL_AUTHORITY) => fault,
        _ => Protocol(MSG_IN_DOUBT),
    }
}

/// Extracts the appended UID from a tagged `[APPENDUID <uidvalidity>
/// <uid-set>]` reply (RFC 4315): the appended UID is the second token
/// after the marker, never the uidvalidity.
fn extract_append_uid(tagged: &str) -> Option<u32> {
    let start = tagged.find("APPENDUID")? + "APPENDUID".len();
    let mut tokens = tagged[start..]
        .split(|c: char| c == '[' || c == ']' || c == '(' || c == ')' || c.is_whitespace())
        .filter(|token| !token.is_empty());
    let _uidvalidity = tokens.next()?;
    let uid_set = tokens.next()?;
    uid_set.split(':').next()?.parse().ok()
}

/// Extracts the destination UID from a tagged `[COPYUID uv src dst]`
/// reply (the UIDPLUS response RFC 6851 requires on MOVE).
fn extract_move_uid(tagged: &str) -> Option<u32> {
    let start = tagged.find("COPYUID")? + "COPYUID".len();
    let rest = tagged[start..].trim_start();
    let mut tokens = rest
        .split(|c: char| c == '(' || c == ')' || c.is_whitespace())
        .filter(|token| !token.is_empty());
    let _uidvalidity = tokens.next()?;
    let _source = tokens.next()?;
    let destination = tokens.next()?;
    destination.split(':').next()?.parse().ok()
}

// ---------------------------------------------------------------------------
// Bounded MIME
// ---------------------------------------------------------------------------

/// The bounded parse of one message header block.
struct ParsedHeaders {
    subject: Option<String>,
    from: Option<String>,
    to: Vec<String>,
    message_id: Option<String>,
    content_type: Option<String>,
    transfer_encoding: Option<String>,
}

fn parse_header_block(block: &str) -> ParsedHeaders {
    let mut parsed = ParsedHeaders {
        subject: None,
        from: None,
        to: Vec::new(),
        message_id: None,
        content_type: None,
        transfer_encoding: None,
    };
    let mut current: Option<(String, String)> = None;
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in block.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = current.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = current.take() {
            fields.push((name, value));
        }
        if let Some((name, value)) = line.split_once(':') {
            current = Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    if let Some(field) = current.take() {
        fields.push(field);
    }
    for (name, value) in fields {
        match name.as_str() {
            "subject" => parsed.subject = Some(value),
            "from" => parsed.from = Some(value),
            "to" => {
                for part in value.split(',') {
                    let part = part.trim();
                    if !part.is_empty() {
                        parsed.to.push(part.to_owned());
                    }
                }
            }
            "message-id" => parsed.message_id = Some(value),
            // MIME parameter values — the multipart boundary above
            // all — are case-sensitive, so the raw value is kept and
            // only comparisons lowercase themselves.
            "content-type" => parsed.content_type = Some(value),
            "content-transfer-encoding" => {
                parsed.transfer_encoding = Some(value.to_ascii_lowercase())
            }
            _ => {}
        }
    }
    parsed
}

/// Extracts the addr-spec of one RFC 5322 address (`Name <a@b>` or
/// `a@b`), bounded.
fn extract_address(value: &str) -> Option<String> {
    let value = value.trim();
    if let (Some(open), Some(close)) = (value.find('<'), value.rfind('>')) {
        if open < close {
            return Some(value[open + 1..close].trim().to_owned());
        }
    }
    if value.is_empty() || value.contains(' ') {
        return None;
    }
    Some(value.to_owned())
}

/// Extracts one Content-Type parameter value. The parameter name is
/// matched case-insensitively; the value keeps its original case —
/// MIME boundaries are case-sensitive.
fn header_param(header: Option<&str>, param: &str) -> Option<String> {
    let header = header?;
    let lowered = header.to_ascii_lowercase();
    let needle = format!("{param}=");
    let index = lowered.find(&needle)? + needle.len();
    let rest = &header[index..];
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_owned());
    }
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim().to_owned())
}

/// Decodes RFC 2047 encoded-words (`=?utf-8?B?…?=` / `=?utf-8?Q?…?=`).
/// Charsets other than UTF-8/US-ASCII pass through untouched; nothing
/// here can panic or exceed its input.
fn decode_rfc2047(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"=?") {
            if let Some((decoded, consumed)) = decode_one_encoded_word(&value[index..]) {
                out.push_str(&decoded);
                index += consumed;
                continue;
            }
        }
        let ch = value[index..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn decode_one_encoded_word(rest: &str) -> Option<(String, usize)> {
    let after_marker = rest.strip_prefix("=?")?;
    let charset_end = after_marker.find('?')?;
    let charset = after_marker[..charset_end].to_ascii_lowercase();
    let after_charset = &after_marker[charset_end + 1..];
    let encoding = after_charset.chars().next()?;
    let after_encoding = &after_charset[encoding.len_utf8() + 1..];
    let text_end = after_encoding.find("?=")?;
    let text = &after_encoding[..text_end];
    let decoded = match encoding.to_ascii_uppercase() {
        'B' => {
            let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = BASE64_STD.decode(cleaned).ok()?;
            String::from_utf8(bytes).ok()?
        }
        'Q' => {
            let bytes = decode_q_word(text);
            String::from_utf8(bytes).ok()?
        }
        _ => return None,
    };
    if !(charset == "utf-8" || charset == "us-ascii") {
        // An unsupported charset is surfaced as the raw word, never as
        // mojibake pretending to be content.
        return None;
    }
    let consumed = rest.len() - after_encoding[text_end + 2..].len();
    Some((decoded, consumed))
}

fn decode_q_word(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => {
                out.push(b' ');
                index += 1;
            }
            b'=' if index + 3 <= bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

fn decode_quoted_printable(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'=' if index + 2 < bytes.len()
                && bytes[index + 1] == b'\r'
                && bytes[index + 2] == b'\n' =>
            {
                index += 3; // soft line break
            }
            b'=' if index + 2 < bytes.len() && bytes[index + 1] == b'\n' => {
                index += 2; // soft line break (bare LF)
            }
            b'=' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

/// Encodes one header or body value as UTF-8 quoted-printable with
/// bounded line lengths.
fn encode_quoted_printable(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut line_len = 0usize;
    for byte in value.as_bytes() {
        let encoded = match byte {
            b'=' => "=3D".to_owned(),
            b'\r' | b'\n' => {
                out.push_str("\r\n");
                line_len = 0;
                continue;
            }
            0x21..=0x7e => (*byte as char).to_string(),
            _ => format!("={byte:02X}"),
        };
        if line_len + encoded.len() > 75 {
            out.push_str("=\r\n");
            line_len = 0;
        }
        out.push_str(&encoded);
        line_len += encoded.len();
    }
    while out.ends_with(' ') || out.ends_with('\t') {
        out.pop();
        out.push_str("=20");
    }
    out
}

fn base64_body_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STD.decode(cleaned).ok()
}

fn latin1_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

fn charset_to_string(charset: &str, bytes: Vec<u8>) -> Result<String, TransportFault> {
    match charset {
        "utf-8" | "us-ascii" => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        "iso-8859-1" | "windows-1252" => Ok(latin1_to_string(&bytes)),
        _ => Err(Protocol(MSG_MIME_CHARSET)),
    }
}

/// Extracts the first supported text/plain body from one message,
/// bounded in parts, depth, and output characters. A message with no
/// extractable text body yields None (honest absence).
fn extract_text_body(message: &[u8], depth: usize) -> Result<Option<String>, TransportFault> {
    if depth > MAX_MIME_DEPTH {
        return Err(Protocol(MSG_MIME));
    }
    let header_end = find_header_end(message).ok_or(Protocol(MSG_MIME))?;
    let headers = parse_header_block(
        std::str::from_utf8(&message[..header_end]).map_err(|_| Protocol(MSG_MIME))?,
    );
    let body = &message[header_end..];
    let content_type = headers.content_type.clone().unwrap_or_default();
    let lowered = content_type.to_ascii_lowercase();
    if lowered.starts_with("multipart/") {
        let Some(boundary) = header_param(Some(&content_type), "boundary") else {
            return Err(Protocol(MSG_MIME));
        };
        return extract_multipart_body(body, &boundary, depth);
    }
    if !lowered.is_empty() && !lowered.starts_with("text/plain") {
        return Ok(None);
    }
    let charset = header_param(Some(&content_type), "charset")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "utf-8".to_owned());
    let decoded = match headers.transfer_encoding.as_deref() {
        Some("base64") => base64_body_decode(body).ok_or(Protocol(MSG_MIME))?,
        Some("quoted-printable") => decode_quoted_printable(body),
        _ => body.to_vec(),
    };
    let text = charset_to_string(&charset, decoded)?;
    Ok(Some(bounded_chars(&text, MAX_BODY_CHARS)))
}

fn split_multipart_parts<'a>(
    body: &'a [u8],
    boundary: &str,
) -> Result<Vec<&'a str>, TransportFault> {
    if boundary.is_empty() || boundary.len() > MAX_LINE_BYTES {
        return Err(Protocol(MSG_MIME));
    }
    let marker = format!("--{boundary}");
    let closer = format!("{marker}--");
    let text = std::str::from_utf8(body).map_err(|_| Protocol(MSG_MIME))?;
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;
    let mut scanned = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let start = scanned;
        scanned += line.len();
        if trimmed == marker || trimmed == closer {
            if let Some(begin) = current.take() {
                parts.push(&text[begin..start]);
                if parts.len() > MAX_MIME_PARTS {
                    return Err(Protocol(MSG_BOUND));
                }
            }
            if trimmed == closer {
                break;
            }
            current = Some(scanned);
        }
    }
    if let Some(begin) = current {
        parts.push(&text[begin..]);
    }
    Ok(parts)
}

fn extract_multipart_body(
    body: &[u8],
    boundary: &str,
    depth: usize,
) -> Result<Option<String>, TransportFault> {
    if depth > MAX_MIME_DEPTH {
        return Err(Protocol(MSG_MIME));
    }
    let parts = split_multipart_parts(body, boundary)?;
    for part in parts {
        let trimmed = part.trim_start_matches(['\r', '\n']);
        let header_end = find_header_end(trimmed.as_bytes()).unwrap_or(0);
        let part_headers = parse_header_block(
            std::str::from_utf8(&trimmed.as_bytes()[..header_end]).unwrap_or(""),
        );
        let content_type = part_headers.content_type.clone().unwrap_or_default();
        let lowered = content_type.to_ascii_lowercase();
        if lowered.starts_with("text/plain") {
            let part_body = &trimmed.as_bytes()[header_end..];
            let charset = header_param(Some(&content_type), "charset")
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_else(|| "utf-8".to_owned());
            let decoded = match part_headers.transfer_encoding.as_deref() {
                Some("base64") => base64_body_decode(part_body).ok_or(Protocol(MSG_MIME))?,
                Some("quoted-printable") => decode_quoted_printable(part_body),
                _ => part_body.to_vec(),
            };
            let text = charset_to_string(&charset, decoded)?;
            return Ok(Some(bounded_chars(&text, MAX_BODY_CHARS)));
        }
        if lowered.starts_with("multipart/") {
            if let Some(found) = extract_multipart_body(
                part.as_bytes(),
                &header_param(Some(&content_type), "boundary").unwrap_or_default(),
                depth + 1,
            )? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

/// Extracts every supported `text/calendar` MIME part. Attachment filenames
/// are allowed (unlike body-text selection); only inline bytes already present
/// in the fetched message are parsed.
fn extract_calendar_invites(
    message: &[u8],
    depth: usize,
) -> Result<Vec<CalendarInvite>, TransportFault> {
    if depth > MAX_MIME_DEPTH {
        return Err(Protocol(MSG_MIME));
    }
    let header_end = find_header_end(message).ok_or(Protocol(MSG_MIME))?;
    let headers = parse_header_block(
        std::str::from_utf8(&message[..header_end]).map_err(|_| Protocol(MSG_MIME))?,
    );
    let body = &message[header_end..];
    let content_type = headers.content_type.clone().unwrap_or_default();
    let lowered = content_type.to_ascii_lowercase();
    if lowered.starts_with("multipart/") {
        let boundary = header_param(Some(&content_type), "boundary").ok_or(Protocol(MSG_MIME))?;
        let mut invitations = Vec::new();
        for part in split_multipart_parts(body, &boundary)? {
            invitations.extend(extract_calendar_invites(
                part.trim_start_matches(['\r', '\n']).as_bytes(),
                depth + 1,
            )?);
            if invitations.len() > crate::email::MAX_CALENDAR_INVITES {
                return Err(Protocol(MSG_BOUND));
            }
        }
        return Ok(invitations);
    }
    if !lowered.starts_with("text/calendar") {
        return Ok(Vec::new());
    }
    let charset = header_param(Some(&content_type), "charset")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "utf-8".to_owned());
    let decoded = match headers.transfer_encoding.as_deref() {
        Some("base64") => base64_body_decode(body).ok_or(Protocol(MSG_MIME))?,
        Some("quoted-printable") => decode_quoted_printable(body),
        _ => body.to_vec(),
    };
    let text = charset_to_string(&charset, decoded)?;
    parse_ical_invites(&text).map_err(|_| Protocol(MSG_ICS))
}

#[cfg(test)]
mod calendar_invite_tests {
    use super::extract_calendar_invites;
    use crate::email::CalendarInviteMethod;

    #[test]
    fn extracts_outlook_style_multipart_calendar_invite() {
        let message = b"MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"parts\"\r\n\r\n--parts\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMeeting moved.\r\n--parts\r\nContent-Type: text/calendar; method=CANCEL; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nBEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:CANCEL\r\nBEGIN:VEVENT\r\nUID:course-42@caltech.edu\r\nSEQUENCE:4\r\nSTATUS:CANCELLED\r\nSUMMARY:Cancelled lecture\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n--parts--\r\n";

        let invitations = extract_calendar_invites(message, 0).expect("invite parses");

        assert_eq!(invitations.len(), 1);
        assert_eq!(invitations[0].method, CalendarInviteMethod::Cancel);
        assert_eq!(invitations[0].uid, "course-42@caltech.edu");
        assert_eq!(invitations[0].sequence, 4);
    }
}

fn find_header_end(message: &[u8]) -> Option<usize> {
    let crlfcrlf = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4);
    let lflf = message
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|index| index + 2);
    match (crlfcrlf, lflf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (one, None) => one,
        (None, one) => one,
    }
}

/// Bounded scan of a raw message: header block, then text body.
fn parse_message_bounded(raw: &[u8]) -> Result<ParsedHeaders, TransportFault> {
    if raw.len() > MAX_SMTP_MESSAGE_BYTES {
        return Err(Protocol(MSG_BOUND));
    }
    let header_end = find_header_end(raw).ok_or(Protocol(MSG_MIME))?;
    if header_end > MAX_HEADER_BLOCK_BYTES {
        return Err(Protocol(MSG_BOUND));
    }
    Ok(parse_header_block(&String::from_utf8_lossy(
        &raw[..header_end],
    )))
}

fn bounded_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

// ---------------------------------------------------------------------------
// Draft MIME construction (bounded)
// ---------------------------------------------------------------------------

/// One constructed draft: its stable Message-ID and its wire bytes.
pub struct DraftMime {
    /// The Message-ID value (without angle brackets).
    pub message_id: String,
    /// The full RFC 5322 message bytes.
    pub bytes: String,
}

/// Builds one bounded text/plain draft message. The Message-ID is
/// derived from a fresh UUID under the configured from domain, so the
/// id the receipt carries is stable and world-unique. Every header
/// value is validated to contain no line breaks before it enters the
/// wire bytes.
pub fn build_draft_mime(
    from_address: &str,
    recipients: &[String],
    subject: &str,
    body_text: &str,
    now: time::OffsetDateTime,
) -> Result<DraftMime, TransportFault> {
    validate_address(from_address)?;
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(Protocol(MSG_BOUND));
    }
    for recipient in recipients {
        validate_address(recipient)?;
    }
    let subject = subject.trim();
    if subject.is_empty()
        || subject.chars().count() > MAX_SUBJECT_CHARS
        || !has_no_controls(subject)
    {
        return Err(Protocol(MSG_BOUND));
    }
    // The body is the one bounded multiline prose field: CRLF pairs
    // are normalized, line feeds survive, every other control is
    // refused.
    let body_text = normalized_multiline(body_text).ok_or(Protocol(MSG_BOUND))?;
    if body_text.chars().count() > MAX_BODY_CHARS {
        return Err(Protocol(MSG_BOUND));
    }
    let domain = from_address.split('@').nth(1).unwrap_or("invalid");
    let message_id = format!("{}@{domain}", uuid::Uuid::new_v4());
    let date = rfc5322_date(now)?;
    let subject_value = if subject.is_ascii() {
        subject.to_owned()
    } else {
        format!("=?utf-8?B?{}?=", BASE64_STD.encode(subject))
    };
    let to_value = recipients
        .iter()
        .map(|address| address.trim().to_owned())
        .collect::<Vec<_>>()
        .join(",\r\n ");
    let body = encode_quoted_printable(&body_text);
    let mime = format!(
        "From: {from_address}\r\n\
         To: {to_value}\r\n\
         Subject: {subject_value}\r\n\
         Date: {date}\r\n\
         Message-ID: <{message_id}>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\
         \r\n\
         {body}\r\n"
    );
    if mime.len() > MAX_SMTP_MESSAGE_BYTES {
        return Err(Protocol(MSG_BOUND));
    }
    Ok(DraftMime {
        message_id,
        bytes: mime,
    })
}

// ---------------------------------------------------------------------------
// SMTP session
// ---------------------------------------------------------------------------

/// One SMTP reply (code plus bounded continuation lines).
struct SmtpReply {
    code: u16,
    lines: Vec<String>,
}

/// One SMTP submission session. STARTTLS is mandatory before
/// authentication whenever the endpoint declares STARTTLS mode, and
/// XOAUTH2 is the only advertised mechanism this client will use.
pub struct SmtpSession {
    stream: MailStream,
    capabilities: Vec<String>,
    authenticated: bool,
    /// The whole-exchange deadline every reply read is armed against.
    deadline: Duration,
    /// When this session was established.
    started: Instant,
}

impl SmtpSession {
    /// Production entry: dials the configured endpoint and enforces the
    /// TLS discipline before returning a session.
    pub fn connect(
        endpoint: &MailEndpoint,
        helo_name: &str,
        deadline: Duration,
    ) -> Result<Self, TransportFault> {
        let tcp = tcp_connect(&endpoint.host, endpoint.port, deadline)?;
        match endpoint.tls {
            TlsMode::ImplicitTls => {
                let tls = tls_client(&endpoint.host, tcp, deadline)?;
                let mut session = Self {
                    stream: MailStream::Tls(Box::new(tls)),
                    capabilities: Vec::new(),
                    authenticated: false,
                    deadline,
                    started: Instant::now(),
                };
                session.expect_greeting()?;
                session.ehlo(helo_name)?;
                Ok(session)
            }
            TlsMode::StartTls => {
                let mut session = Self {
                    stream: MailStream::Plain(tcp),
                    capabilities: Vec::new(),
                    authenticated: false,
                    deadline,
                    started: Instant::now(),
                };
                session.expect_greeting()?;
                session.ehlo(helo_name)?;
                if !session.has_capability("STARTTLS") {
                    // Refuse before any credential or message byte is
                    // sent: a typed pre-dispatch refusal.
                    return Err(TransportFault::Refused(MSG_STARTTLS));
                }
                write_all(&mut session.stream, b"STARTTLS\r\n")?;
                let reply = session.reply()?;
                if reply.code != 220 {
                    return Err(Protocol(MSG_STARTTLS));
                }
                let plain = match &mut session.stream {
                    MailStream::Plain(tcp) => tcp.try_clone().map_err(|_| Protocol(MSG_TLS))?,
                    MailStream::Tls(_) => return Err(Protocol(MSG_TLS)),
                };
                let tls = tls_client(&endpoint.host, plain, deadline)?;
                session.stream = MailStream::Tls(Box::new(tls));
                session.ehlo(helo_name)?;
                Ok(session)
            }
        }
    }

    /// Scripted-test seam: wraps an already-connected plaintext loopback
    /// stream and consumes the greeting the script has written.
    pub fn over_insecure_stream(stream: TcpStream) -> Result<Self, TransportFault> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| Protocol(MSG_IO))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| Protocol(MSG_IO))?;
        let mut session = Self {
            stream: MailStream::Plain(stream),
            capabilities: Vec::new(),
            authenticated: false,
            deadline: Duration::from_secs(10),
            started: Instant::now(),
        };
        session.expect_greeting()?;
        Ok(session)
    }

    /// Arms the remaining exchange deadline, then reads one reply: no
    /// server can dribble a submission past its bound.
    fn reply(&mut self) -> Result<SmtpReply, TransportFault> {
        let Some(remaining) = self.deadline.checked_sub(self.started.elapsed()) else {
            return Err(TransportFault::Timeout);
        };
        let socket = match &mut self.stream {
            MailStream::Plain(tcp) => tcp,
            MailStream::Tls(tls) => tls.get_mut(),
        };
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| Protocol(MSG_IO))?;
        socket
            .set_write_timeout(Some(remaining))
            .map_err(|_| Protocol(MSG_IO))?;
        read_smtp_reply(&mut self.stream)
    }

    fn expect_greeting(&mut self) -> Result<(), TransportFault> {
        let reply = self.reply()?;
        if reply.code == 220 {
            Ok(())
        } else {
            Err(Protocol(MSG_SMTP_REJECTED))
        }
    }

    fn ehlo(&mut self, helo_name: &str) -> Result<(), TransportFault> {
        write_all(&mut self.stream, format!("EHLO {helo_name}\r\n").as_bytes())?;
        let reply = self.reply()?;
        if reply.code != 250 {
            return Err(Protocol(MSG_SMTP_REJECTED));
        }
        self.capabilities = reply.lines;
        Ok(())
    }

    fn has_capability(&self, name: &str) -> bool {
        self.capabilities
            .iter()
            .any(|line| line.trim().eq_ignore_ascii_case(name))
    }

    fn has_xoauth2(&self) -> bool {
        self.capabilities.iter().any(|line| {
            let line = line.trim();
            (line.starts_with("AUTH ") || line.starts_with("AUTH="))
                && line.to_ascii_uppercase().contains("XOAUTH2")
        })
    }

    /// Authenticates with XOAUTH2 only. A 334 challenge is answered
    /// with the mandated empty continuation; the failure text is never
    /// surfaced.
    pub fn authenticate_xoauth2(
        &mut self,
        credentials: &MailCredentials,
    ) -> Result<(), TransportFault> {
        if !self.has_xoauth2() {
            return Err(TransportFault::Refused(MSG_NO_XOAUTH2));
        }
        let payload = xoauth2_client_response(&credentials.user, &credentials.access_token);
        write_all(
            &mut self.stream,
            format!("AUTH XOAUTH2 {payload}\r\n").as_bytes(),
        )?;
        let reply = self.reply()?;
        if reply.code == 235 {
            self.authenticated = true;
            return Ok(());
        }
        if reply.code == 334 {
            write_all(&mut self.stream, b"\r\n")?;
            let reply = self.reply()?;
            if reply.code == 235 {
                self.authenticated = true;
                return Ok(());
            }
        }
        Err(TransportFault::Unavailable(AccountUnavailable::Credentials))
    }

    /// Submits one bounded message over the authenticated session. The
    /// message is dot-stuffed per RFC 5321; recipients are bounded.
    pub fn send_message(
        &mut self,
        from_address: &str,
        recipients: &[String],
        message: &str,
    ) -> Result<(), TransportFault> {
        if !self.authenticated {
            return Err(Protocol(MSG_NOT_AUTH));
        }
        if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
            return Err(Protocol(MSG_BOUND));
        }
        if message.len() > MAX_SMTP_MESSAGE_BYTES {
            return Err(Protocol(MSG_BOUND));
        }
        write_all(
            &mut self.stream,
            format!("MAIL FROM:<{from_address}>\r\n").as_bytes(),
        )?;
        if self.reply()?.code != 250 {
            return Err(Protocol(MSG_SMTP_REJECTED));
        }
        for recipient in recipients {
            write_all(
                &mut self.stream,
                format!("RCPT TO:<{}>\r\n", recipient.trim()).as_bytes(),
            )?;
            if self.reply()?.code != 250 {
                return Err(Protocol(MSG_SMTP_REJECTED));
            }
        }
        write_all(&mut self.stream, b"DATA\r\n")?;
        if self.reply()?.code != 354 {
            return Err(Protocol(MSG_SMTP_REJECTED));
        }
        write_all(&mut self.stream, dot_stuff(message).as_bytes())?;
        write_all(&mut self.stream, b".\r\n")?;
        // The message bytes and the terminating dot are on the wire:
        // the submission is committed. Whatever happens now is
        // in-doubt — a definitive rejection stays typed, an unknowable
        // outcome never masquerades as a clean retryable failure.
        match self.reply() {
            Ok(reply) if reply.code == 250 => Ok(()),
            Ok(_) => Err(Protocol(MSG_SMTP_REJECTED)),
            Err(fault) => Err(in_doubt_fault(fault)),
        }
    }

    /// Best-effort QUIT; failures never surface.
    pub fn quit(&mut self) {
        let _ = write_all(&mut self.stream, b"QUIT\r\n");
    }
}

fn read_smtp_reply(stream: &mut MailStream) -> Result<SmtpReply, TransportFault> {
    let mut lines = Vec::new();
    loop {
        let line = read_line_bounded(stream, MAX_LINE_BYTES)?;
        let bytes = line.as_bytes();
        if bytes.len() < 3 || !bytes[..3].iter().all(|b| b.is_ascii_digit()) {
            return Err(Protocol(MSG_SMTP_REJECTED));
        }
        let code: u16 = line[..3].parse().map_err(|_| Protocol(MSG_SMTP_REJECTED))?;
        let final_reply = bytes.len() == 3 || bytes[3] != b'-';
        if final_reply {
            if lines.len() >= MAX_SMTP_REPLY_LINES {
                return Err(Protocol(MSG_BOUND));
            }
            lines.push(line[4.min(line.len())..].to_owned());
            return Ok(SmtpReply { code, lines });
        }
        lines.push(line[4..].to_owned());
        if lines.len() > MAX_SMTP_REPLY_LINES {
            return Err(Protocol(MSG_BOUND));
        }
    }
}

/// RFC 5321 dot-stuffing with CRLF normalization.
fn dot_stuff(message: &str) -> String {
    let mut out = String::with_capacity(message.len() + 16);
    for line in message.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

// ---------------------------------------------------------------------------
// CalDAV over WebDAV: the trusted HTTP seam
// ---------------------------------------------------------------------------

/// The authorization carried on one calendar request. The variants hold
/// redacted secret wrappers; nothing here ever formats the values.
#[derive(Clone)]
pub enum CaldavAuth {
    None,
    /// The XOAUTH2 bearer for direct HTTPS calendar endpoints.
    Bearer(AccessToken),
    /// A separately provisioned CalDAV Basic pair.
    Basic {
        user: String,
        password: Password,
    },
}

impl std::fmt::Debug for CaldavAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => formatter.write_str("CaldavAuth::None"),
            Self::Bearer(_) => formatter.write_str("CaldavAuth::Bearer([REDACTED])"),
            Self::Basic { user, .. } => formatter
                .debug_struct("CaldavAuth::Basic")
                .field("user", user)
                .field("password", &"[REDACTED]")
                .finish(),
        }
    }
}

/// One calendar HTTP request. `destination` carries the MOVE target;
/// `if_match`/`if_none_match` drive the conditional PUTs.
pub struct CaldavHttpRequest {
    pub method: &'static str,
    pub url: String,
    pub auth: CaldavAuth,
    pub depth: Option<&'static str>,
    pub content_type: Option<&'static str>,
    pub body: Option<Vec<u8>>,
    pub destination: Option<String>,
    pub if_match: Option<String>,
    pub if_none_match: bool,
}

impl std::fmt::Debug for CaldavHttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaldavHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("auth", &self.auth)
            .field("depth", &self.depth)
            .field("content_type", &self.content_type)
            .field("body", &self.body.as_ref().map(|b| b.len()))
            .field("destination", &self.destination)
            .field("if_match", &self.if_match)
            .field("if_none_match", &self.if_none_match)
            .finish()
    }
}

/// One calendar HTTP response.
#[derive(Clone, Debug)]
pub struct CaldavHttpResponse {
    pub status: u16,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

/// Implementations must classify dispatch uncertainty correctly and never follow redirects.
pub trait CaldavHttp: Send + Sync {
    fn dispatch(&self, request: CaldavHttpRequest) -> Result<CaldavHttpResponse, TransportFault>;
}

/// The production calendar exchange: `reqwest::blocking` with redirects
/// disabled, loopback-only HTTP, HTTPS elsewhere, hard response-byte
/// ceiling, and the authorization header built from redacted
/// credential wrappers at dispatch time.
pub struct HttpsCaldavExchange {
    deadline: Duration,
    max_bytes: u64,
}

impl HttpsCaldavExchange {
    pub fn new(deadline: Duration, max_bytes: u64) -> Self {
        Self {
            deadline,
            max_bytes,
        }
    }
}

fn map_http_error(error: reqwest::Error) -> TransportFault {
    if error.is_timeout() {
        return TransportFault::Timeout;
    }
    if error.is_connect() || error.is_request() {
        return TransportFault::Unavailable(AccountUnavailable::Service);
    }
    if error.is_body() || error.is_decode() {
        return Protocol(MSG_HTTP);
    }
    Protocol(MSG_HTTP)
}

impl CaldavHttp for HttpsCaldavExchange {
    fn dispatch(&self, request: CaldavHttpRequest) -> Result<CaldavHttpResponse, TransportFault> {
        // The URL policy is enforced here as well as at configuration
        // time: a caller-supplied URL can never ride around it.
        let url = validate_caldav_url(&request.url)?;
        let client = crate::http_pool::no_redirect().map_err(|_| Protocol(MSG_HTTP))?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| Protocol(MSG_HTTP))?;
        let mut builder = client.request(method, url.clone()).timeout(self.deadline);
        match &request.auth {
            CaldavAuth::None => {}
            CaldavAuth::Bearer(token) => builder = builder.bearer_auth(token.0.clone()),
            CaldavAuth::Basic { user, password } => {
                builder = builder.basic_auth(user.clone(), Some(password.0.clone()))
            }
        }
        if let Some(depth) = request.depth {
            let name = reqwest::header::HeaderName::from_bytes(b"Depth")
                .map_err(|_| Protocol(MSG_HTTP))?;
            builder = builder.header(name, depth);
        }
        if let Some(content_type) = request.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        if let Some(destination) = &request.destination {
            let parsed = validate_caldav_url(destination)?;
            // A MOVE target may never leave the origin the request is
            // authenticated against.
            if parsed.origin() != url.origin() {
                return Err(Protocol(MSG_URL_AUTHORITY));
            }
            let name = reqwest::header::HeaderName::from_bytes(b"Destination")
                .map_err(|_| Protocol(MSG_HTTP))?;
            builder = builder.header(name, parsed.as_str().to_owned());
        }
        if let Some(etag) = &request.if_match {
            builder = builder.header(reqwest::header::IF_MATCH, etag.clone());
        }
        if request.if_none_match {
            builder = builder.header(reqwest::header::IF_NONE_MATCH, "*");
        }
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }
        let response = builder.send().map_err(map_http_error)?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(Protocol(MSG_REDIRECT));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                // An opaque ETag is never truncated: an overlong
                // validator is a bounds fault, never a silently
                // mismatched If-Match.
                if value.chars().count() > MAX_ETAG_CHARS {
                    return Err(Protocol(MSG_BOUND));
                }
                Ok(value.to_owned())
            })
            .transpose()?;
        let mut bytes = Vec::new();
        let mut reader = response.take(self.max_bytes.saturating_add(1));
        use std::io::Read as _;
        reader
            .read_to_end(&mut bytes)
            .map_err(|_| Protocol(MSG_HTTP))?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(Protocol(MSG_BOUND));
        }
        Ok(CaldavHttpResponse {
            status,
            etag,
            body: bytes,
        })
    }
}

// ---------------------------------------------------------------------------
// Bounded XML: REPORT body and multistatus parsing
// ---------------------------------------------------------------------------

/// Builds the `calendar-query` REPORT body for one UTC window. The
/// arguments are basic-UTC strings produced by `ics_utc`, so no
/// user text enters the XML. The server expands recurring series into
/// their instances in the window, in UTC (RFC 4791 §9.6.5): a weekly
/// class is one event per meeting, not its first meeting.
pub fn calendar_query_report(start_basic: &str, end_basic: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
         <D:prop><D:getetag/><C:calendar-data>\
         <C:expand start=\"{start_basic}\" end=\"{end_basic}\"/>\
         </C:calendar-data></D:prop>\
         <C:filter><C:comp-filter name=\"VCALENDAR\">\
         <C:comp-filter name=\"VEVENT\">\
         <C:time-range start=\"{start_basic}\" end=\"{end_basic}\"/>\
         </C:comp-filter></C:comp-filter></C:filter>\
         </C:calendar-query>"
    )
}
/// Unescapes the XML entities the multistatus documents may carry,
/// bounded to its input. Returns the decoded bytes and the number of
/// input bytes consumed.
fn parse_entity(rest: &[u8]) -> Option<(Vec<u8>, usize)> {
    let end = rest.iter().position(|&b| b == b';')? + 1;
    if rest.starts_with(b"&lt;") {
        return Some((b"<".to_vec(), 4));
    }
    if rest.starts_with(b"&gt;") {
        return Some((b">".to_vec(), 4));
    }
    if rest.starts_with(b"&amp;") {
        return Some((b"&".to_vec(), 5));
    }
    if rest.starts_with(b"&quot;") {
        return Some((b"\"".to_vec(), 6));
    }
    if rest.starts_with(b"&apos;") {
        return Some((b"'".to_vec(), 6));
    }
    if rest.starts_with(b"&#x") || rest.starts_with(b"&#X") {
        let digits = std::str::from_utf8(&rest[3..end - 1]).ok()?;
        let code = u32::from_str_radix(digits, 16).ok()?;
        return Some((char::from_u32(code)?.to_string().into_bytes(), end));
    }
    if rest.starts_with(b"&#") {
        let digits = std::str::from_utf8(&rest[2..end - 1]).ok()?;
        let code = digits.parse::<u32>().ok()?;
        return Some((char::from_u32(code)?.to_string().into_bytes(), end));
    }
    None
}

/// Unescapes the XML entities of one bounded byte run.
fn unescape_xml(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut index = 0usize;
    while index < text.len() {
        if text[index] == b'&' {
            if let Some((bytes, consumed)) = parse_entity(&text[index..]) {
                out.extend_from_slice(&bytes);
                index += consumed;
                continue;
            }
        }
        out.push(text[index]);
        index += 1;
    }
    out
}

/// One multistatus entry: its calendar-data blob, absent for container
/// responses.
struct CaldavItem {
    calendar_data: Option<Vec<u8>>,
}

/// Parses one bounded multistatus document into its entries. Local
/// element names are matched namespace-agnostically; anything
/// off-shape or over-bounds is a typed protocol fault.
fn parse_multistatus(bytes: &[u8]) -> Result<Vec<CaldavItem>, TransportFault> {
    let mut items: Vec<CaldavItem> = Vec::new();
    let mut current: Option<CaldavItem> = None;
    let mut capture: Option<&'static str> = None;
    let mut buf: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some(offset) = bytes[pos..].iter().position(|&byte| byte == b'<') else {
            break;
        };
        if capture.is_some() {
            buf.extend_from_slice(&unescape_xml(&bytes[pos..pos + offset]));
            if buf.len() > MAX_ICS_EVENT_BYTES.max(MAX_URL_CHARS) {
                return Err(Protocol(MSG_BOUND));
            }
        }
        pos += offset + 1;
        let Some(close) = bytes[pos..].iter().position(|&byte| byte == b'>') else {
            return Err(Protocol(MSG_XML));
        };
        let raw_tag = &bytes[pos..pos + close];
        pos += close + 1;
        let (closing, name) = {
            let stripped = raw_tag.strip_prefix(b"/").unwrap_or(raw_tag);
            let self_closing = stripped.ends_with(b"/");
            let stripped = stripped.strip_suffix(b"/").unwrap_or(stripped);
            let end = stripped
                .iter()
                .position(|byte| *byte == b' ' || *byte == b'\t')
                .unwrap_or(stripped.len());
            let full = std::str::from_utf8(&stripped[..end]).map_err(|_| Protocol(MSG_XML))?;
            let local = full.rsplit(':').next().unwrap_or(full);
            let closing = raw_tag.first() == Some(&b'/') || self_closing;
            (closing, local.to_ascii_lowercase())
        };
        match (closing, name.as_str()) {
            (false, "response") => {
                if items.len() >= MAX_EVENTS {
                    return Err(Protocol(MSG_BOUND));
                }
                current = Some(CaldavItem {
                    calendar_data: None,
                });
            }
            (false, "calendar-data") => {
                capture = Some("calendar-data");
                buf.clear();
            }
            // Hrefs are not consumed by this surface: identities are
            // the iCalendar UIDs, so hrefs are skipped entirely.
            (true, "href") => {
                capture = None;
            }
            (true, "calendar-data") => {
                if capture == Some("calendar-data") {
                    let value = std::mem::take(&mut buf);
                    if let Some(item) = current.as_mut() {
                        item.calendar_data = Some(value);
                    }
                    capture = None;
                }
            }
            (true, "response") => {
                if let Some(item) = current.take() {
                    items.push(item);
                }
            }
            _ => {}
        }
    }
    Ok(items)
}

// ---------------------------------------------------------------------------
// Bounded iCalendar
// ---------------------------------------------------------------------------

/// Escapes one RFC 5545 text value.
fn ics_text_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' | '\r' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Unescapes one RFC 5545 text value.
fn ics_text_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            match ch {
                'n' | 'N' => out.push('\n'),
                other => out.push(other),
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        out.push(ch);
    }
    out
}

/// Folds an iCalendar document into bounded logical lines (RFC 5545
/// unfolding).
fn unfold_ics(text: &str) -> Result<Vec<String>, TransportFault> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.is_empty() {
            continue;
        }
        if raw.starts_with(' ') || raw.starts_with('\t') {
            let Some(last) = lines.last_mut() else {
                return Err(Protocol(MSG_ICS));
            };
            last.push_str(&raw[1..]);
            if last.len() > 4_096 {
                return Err(Protocol(MSG_BOUND));
            }
            continue;
        }
        lines.push(raw.to_owned());
        if lines.len() > 512 {
            return Err(Protocol(MSG_BOUND));
        }
    }
    Ok(lines)
}

/// One parsed VEVENT: the stable identity and content fields this
/// surface consumes, plus the unfolded lines the rewrites operate on.
struct IcsEvent {
    uid: String,
    summary: Option<String>,
    description: Option<String>,
    /// Present when the times are UTC (`…Z`) or local to a zone the
    /// tz database names exactly. A timezone-local time is never guessed
    /// as UTC, so a `zoned` event in an unknown zone carries no instants.
    dtstart: Option<time::OffsetDateTime>,
    dtend: Option<time::OffsetDateTime>,
    /// At least one of DTSTART/DTEND is timezone-local (a TZID
    /// parameter): the event keeps its zone identity instead of being
    /// coerced to UTC.
    zoned: bool,
}

fn property_name(line: &str) -> &str {
    let name = line.split(':').next().unwrap_or("");
    name.split(';').next().unwrap_or("")
}

fn property_value(line: &str) -> &str {
    line.split_once(':').map(|(_, value)| value).unwrap_or("")
}

fn property_has_param(line: &str, param: &str) -> bool {
    let Some((name_part, _)) = line.split_once(':') else {
        return false;
    };
    name_part.split(';').skip(1).any(|piece| {
        piece.trim().eq_ignore_ascii_case(param)
            || piece
                .trim()
                .to_ascii_uppercase()
                .starts_with(&param.to_ascii_uppercase())
    })
}

/// Parses the first VEVENT of one bounded iCalendar blob. UID is
/// required. TZID-local times do not abort the parse: the event is
/// reported as `zoned` with its UTC instants absent, so the window
/// read can skip it honestly and a cancel can still rewrite its
/// status without touching its times.
fn parse_ics(lines: &[String]) -> Result<IcsEvent, TransportFault> {
    let begin = lines
        .iter()
        .position(|line| line.eq_ignore_ascii_case("BEGIN:VEVENT"))
        .ok_or(Protocol(MSG_ICS))?;
    let end = lines[begin..]
        .iter()
        .position(|line| line.eq_ignore_ascii_case("END:VEVENT"))
        .map(|offset| begin + offset)
        .ok_or(Protocol(MSG_ICS))?;
    let mut uid: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut description: Option<String> = None;
    let mut dtstart: Option<time::OffsetDateTime> = None;
    let mut dtend: Option<time::OffsetDateTime> = None;
    let mut zoned = false;
    for line in &lines[begin + 1..end] {
        let name = property_name(line).to_ascii_uppercase();
        match name.as_str() {
            "UID" => uid = Some(property_value(line).trim().to_owned()),
            "SUMMARY" => summary = Some(ics_text_unescape(property_value(line))),
            "DESCRIPTION" => description = Some(ics_text_unescape(property_value(line))),
            "DTSTART" | "DTEND" => {
                let instant = if property_has_param(line, "TZID") {
                    zoned = true;
                    match zoned_instant(line) {
                        Some(instant) => instant,
                        None => continue,
                    }
                } else {
                    ics_to_rfc3339(property_value(line))?
                };
                if name == "DTSTART" {
                    dtstart = Some(instant);
                } else {
                    dtend = Some(instant);
                }
            }
            _ => {}
        }
    }
    let uid = uid
        .filter(|value| !value.is_empty())
        .ok_or(Protocol(MSG_ICS))?;
    if !zoned {
        dtstart = Some(dtstart.ok_or(Protocol(MSG_ICS))?);
        dtend = Some(dtend.ok_or(Protocol(MSG_ICS))?);
    }
    Ok(IcsEvent {
        uid,
        summary,
        description,
        dtstart,
        dtend,
        zoned,
    })
}

/// Every VEVENT block of one unfolded iCalendar blob: an expanded
/// recurring series is one block per instance.
fn vevent_blocks(lines: &[String]) -> Vec<&[String]> {
    let mut blocks = Vec::new();
    let mut begin = None;
    for (index, line) in lines.iter().enumerate() {
        if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
            begin = Some(index);
        } else if line.eq_ignore_ascii_case("END:VEVENT") {
            if let Some(start) = begin.take() {
                blocks.push(&lines[start..=index]);
            }
        }
    }
    blocks
}

/// Windows zone names Outlook and Exchange write as TZID, for the US
/// zones a Caltech calendar uses.
const WINDOWS_ZONES: [(&str, &str); 6] = [
    ("Pacific Standard Time", "America/Los_Angeles"),
    ("Mountain Standard Time", "America/Denver"),
    ("US Mountain Standard Time", "America/Phoenix"),
    ("Central Standard Time", "America/Chicago"),
    ("Eastern Standard Time", "America/New_York"),
    ("UTC", "UTC"),
];

/// The exact instant of a `DTSTART;TZID=<zone>:YYYYMMDDTHHMMSS` line when
/// the tz database (or the Windows name table) knows the zone; `None`
/// otherwise — an unknown zone is never guessed.
fn zoned_instant(line: &str) -> Option<time::OffsetDateTime> {
    let (name_part, value) = line.split_once(':')?;
    let tzid = name_part.split(';').skip(1).find_map(|piece| {
        let (key, value) = piece.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("TZID")
            .then(|| value.trim().trim_matches('"'))
    })?;
    let tzid = WINDOWS_ZONES
        .iter()
        .find(|(windows, _)| windows.eq_ignore_ascii_case(tzid))
        .map_or(tzid, |(_, iana)| iana);
    let zone = jiff::tz::TimeZone::get(tzid).ok()?;
    let local: jiff::civil::DateTime = jiff::fmt::strtime::parse("%Y%m%dT%H%M%S", value.trim())
        .ok()?
        .to_datetime()
        .ok()?;
    let instant = local.to_zoned(zone).ok()?.timestamp();
    time::OffsetDateTime::from_unix_timestamp(instant.as_second()).ok()
}

/// Sets (or inserts before `END:VEVENT`) one property on the unfolded
/// line list, dropping parameters from any line it replaces.
fn set_ics_property(lines: &mut Vec<String>, name: &str, value: &str) {
    let target = name.to_ascii_uppercase();
    let mut replaced = false;
    for line in lines.iter_mut() {
        if property_name(line).to_ascii_uppercase() == target {
            *line = format!("{name}:{value}");
            replaced = true;
            break;
        }
    }
    if !replaced {
        let position = lines
            .iter()
            .position(|line| line.eq_ignore_ascii_case("END:VEVENT"))
            .unwrap_or(lines.len());
        lines.insert(position, format!("{name}:{value}"));
    }
}

/// Bumps the iCalendar SEQUENCE (per RFC 5545 it defaults to zero
/// when absent) so every rewrite carries a fresh revision.
fn bump_ics_sequence(lines: &mut Vec<String>) {
    for line in lines.iter_mut() {
        if property_name(line).eq_ignore_ascii_case("SEQUENCE") {
            let sequence = property_value(line).trim().parse::<u32>().unwrap_or(0);
            *line = format!("SEQUENCE:{}", sequence.saturating_add(1));
            return;
        }
    }
    let position = lines
        .iter()
        .position(|line| line.eq_ignore_ascii_case("END:VEVENT"))
        .unwrap_or(lines.len());
    lines.insert(position, "SEQUENCE:1".to_owned());
}

/// Asserts the parsed event carries exactly the addressed UID.
fn ensure_ics_uid(event: &IcsEvent, event_id: &str) -> Result<(), TransportFault> {
    if event.uid == event_id {
        Ok(())
    } else {
        Err(Protocol(MSG_ICS_UID))
    }
}

fn validate_event_draft(
    draft: &CalendarEventDraft,
) -> Result<(time::OffsetDateTime, time::OffsetDateTime), TransportFault> {
    let title = draft.title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE_CHARS || !has_no_controls(title) {
        return Err(Protocol(MSG_PROPOSAL));
    }
    let start = parse_rfc3339_whole(&draft.start)?;
    let end = parse_rfc3339_whole(&draft.end)?;
    if end <= start || (end - start).whole_days() > MAX_WINDOW_DAYS {
        return Err(Protocol(MSG_PROPOSAL));
    }
    if let Some(location) = &draft.location {
        if location.chars().count() > MAX_LOCATION_CHARS || !has_no_controls(location) {
            return Err(Protocol(MSG_PROPOSAL));
        }
    }
    if let Some(description) = &draft.description {
        // The description is the one bounded multiline prose field of
        // an event: CRLF pairs normalize, line feeds survive, every
        // other control is refused.
        let Some(normalized) = normalized_multiline(description) else {
            return Err(Protocol(MSG_PROPOSAL));
        };
        if normalized.chars().count() > MAX_EVENT_DESCRIPTION_CHARS {
            return Err(Protocol(MSG_PROPOSAL));
        }
    }
    Ok((start, end))
}

/// Builds one bounded VCALENDAR document for a concrete single event
/// (no recurrence is ever invented).
fn build_ics(
    draft: &CalendarEventDraft,
    uid: &str,
    now: time::OffsetDateTime,
) -> Result<String, TransportFault> {
    let (start, end) = validate_event_draft(draft)?;
    let stamp = ics_utc(now)?;
    let mut lines = vec![
        "BEGIN:VCALENDAR".to_owned(),
        "VERSION:2.0".to_owned(),
        "PRODID:-//odin-life//generic-provider//EN".to_owned(),
        "CALSCALE:GREGORIAN".to_owned(),
        "BEGIN:VEVENT".to_owned(),
        format!("UID:{uid}"),
        format!("DTSTAMP:{stamp}"),
        format!("DTSTART:{}", ics_utc(start)?),
        format!("DTEND:{}", ics_utc(end)?),
        format!("SUMMARY:{}", ics_text_escape(draft.title.trim())),
    ];
    if let Some(location) = draft
        .location
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        lines.push(format!("LOCATION:{}", ics_text_escape(location)));
    }
    if let Some(description) = draft
        .description
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let normalized = normalized_multiline(description).ok_or(Protocol(MSG_PROPOSAL))?;
        lines.push(format!("DESCRIPTION:{}", ics_text_escape(&normalized)));
    }
    lines.push("END:VEVENT".to_owned());
    lines.push("END:VCALENDAR".to_owned());
    let mut body = lines.join("\r\n");
    body.push_str("\r\n");
    Ok(body)
}

// ---------------------------------------------------------------------------
// The generic provider
// ---------------------------------------------------------------------------

/// The production generic provider: real IMAP/SMTP mail with XOAUTH2
/// and real CalDAV over the trusted HTTP seam, bounded end to end,
/// with no destroy path anywhere. It serves exactly its configured
/// account over the account router's provider port.
#[derive(Clone)]
pub struct GenericLifeProvider {
    config: GenericProviderConfig,
    caldav_http: Arc<dyn CaldavHttp>,
}

impl GenericLifeProvider {
    /// Validates the deployment facts and binds the calendar seam.
    pub fn new(
        config: GenericProviderConfig,
        caldav_http: Arc<dyn CaldavHttp>,
    ) -> Result<Self, TransportFault> {
        Ok(Self {
            config: config.validated()?,
            caldav_http,
        })
    }

    /// Resolves calendar authorization for one exchange. A separately
    /// provisioned CalDAV Basic pair always wins; HTTPS without that pair
    /// falls back to the account bearer for direct OAuth-capable CalDAV.
    /// Plain loopback HTTP requires Basic so a bearer is never sent in clear.
    fn caldav_auth(
        &self,
        lease: &ScopedCredentialLease,
        operation: &'static str,
        now: time::OffsetDateTime,
    ) -> Result<CaldavAuth, TransportFault> {
        let caldav = self.config.caldav.as_ref().ok_or(Protocol(MSG_NO_CALDAV))?;
        let scheme = validate_caldav_url(&caldav.base_url)?.scheme().to_owned();
        let credentials = resolve_mail_credentials(
            &self.config.account,
            &self.config.credential,
            lease,
            operation,
            now,
            self.config.deadline(),
        )?;
        if let Some(caldav_basic) = credentials.caldav_basic {
            return Ok(CaldavAuth::Basic {
                user: caldav_basic.user,
                password: caldav_basic.password,
            });
        }
        if scheme == "https" {
            Ok(CaldavAuth::Bearer(credentials.access_token))
        } else {
            Err(Protocol(MSG_NO_CALDAV_BASIC))
        }
    }

    fn event_url(&self, collection: &str, event_id: &str) -> Result<String, TransportFault> {
        validate_event_id(event_id)?;
        Ok(format!("{collection}/{event_id}.ics"))
    }

    /// Renders one new event into its UID, URL, and iCalendar body.
    /// No dispatch happens here: batches render fully before the first
    /// PUT so a bad draft can never leave a partial batch behind.
    fn prepare_new_event(
        &self,
        collection: &str,
        draft: &CalendarEventDraft,
        now: time::OffsetDateTime,
    ) -> Result<(String, String, String), TransportFault> {
        let uid = uuid::Uuid::new_v4().to_string();
        let body = build_ics(draft, &uid, now)?;
        let url = self.event_url(collection, &uid)?;
        Ok((uid, url, body))
    }

    /// Puts one rendered new event. A fault from the seam is
    /// in-doubt: the PUT may have taken effect, so it never looks
    /// like a clean retryable failure.
    fn put_new_event(
        &self,
        url: &str,
        auth: &CaldavAuth,
        body: &str,
    ) -> Result<(), TransportFault> {
        let response = self
            .caldav_http
            .dispatch(CaldavHttpRequest {
                method: "PUT",
                url: url.to_owned(),
                auth: auth.clone(),
                depth: None,
                content_type: Some("text/calendar; charset=utf-8"),
                body: Some(body.as_bytes().to_vec()),
                destination: None,
                if_match: None,
                if_none_match: true,
            })
            .map_err(in_doubt_fault)?;
        if !(200..300).contains(&response.status) {
            return Err(Protocol(MSG_CALDAV_STATUS));
        }
        Ok(())
    }

    /// Fetches one event resource for a read-modify-write rewrite.
    fn fetch_event_lines(
        &self,
        url: &str,
        auth: &CaldavAuth,
    ) -> Result<(Vec<String>, String), TransportFault> {
        let response = self.caldav_http.dispatch(CaldavHttpRequest {
            method: "GET",
            url: url.to_owned(),
            auth: auth.clone(),
            depth: None,
            content_type: None,
            body: None,
            destination: None,
            if_match: None,
            if_none_match: false,
        })?;
        if response.status != 200 {
            return Err(Protocol(MSG_CALDAV_STATUS));
        }
        if response.body.len() > MAX_ICS_EVENT_BYTES {
            return Err(Protocol(MSG_BOUND));
        }
        let etag = response.etag.clone().filter(|value| !value.is_empty());
        let etag = etag.ok_or(Protocol(MSG_CALDAV_STATUS))?;
        // An opaque ETag is never truncated: an overlong validator is
        // a bounds fault, never a silently mismatched If-Match.
        if etag.chars().count() > MAX_ETAG_CHARS {
            return Err(Protocol(MSG_BOUND));
        }
        let text = String::from_utf8(response.body).map_err(|_| Protocol(MSG_ICS))?;
        let lines = unfold_ics(&text)?;
        Ok((lines, etag))
    }

    fn put_event_lines(
        &self,
        url: &str,
        auth: &CaldavAuth,
        lines: &[String],
        etag: &str,
    ) -> Result<(), TransportFault> {
        let mut body = lines.join("\r\n");
        body.push_str("\r\n");
        let response = self
            .caldav_http
            .dispatch(CaldavHttpRequest {
                method: "PUT",
                url: url.to_owned(),
                auth: auth.clone(),
                depth: None,
                content_type: Some("text/calendar; charset=utf-8"),
                body: Some(body.into_bytes()),
                destination: None,
                if_match: Some(etag.to_owned()),
                if_none_match: false,
            })
            .map_err(in_doubt_fault)?;
        if !(200..300).contains(&response.status) {
            return Err(Protocol(MSG_CALDAV_STATUS));
        }
        Ok(())
    }
}

impl crate::provider::LifeProvider for GenericLifeProvider {
    fn email_transport(&self, account: &str) -> Option<Arc<dyn EmailTransport>> {
        (account == self.config.account).then(|| Arc::new(self.clone()) as Arc<dyn EmailTransport>)
    }

    fn calendar_transport(&self, account: &str) -> Option<Arc<dyn CalendarTransport>> {
        (account == self.config.account && self.config.caldav.is_some())
            .then(|| Arc::new(self.clone()) as Arc<dyn CalendarTransport>)
    }
}

mod mail;

impl GenericLifeProvider {
    /// Checks account and credential-file readiness without issuing a lease, refreshing, or connecting.
    fn credential_readiness(&self, account: &str) -> Result<(), TransportFault> {
        if account != self.config.account {
            return Err(TransportFault::Unavailable(AccountUnavailable::Account));
        }
        load_credential_file(account, &self.config.credential).map(drop)
    }
}

impl CalendarTransport for GenericLifeProvider {
    /// A provider without a declared CalDAV endpoint serves no calendar.
    fn readiness(&self, account: &str) -> Result<(), TransportFault> {
        if self.config.caldav.is_none() {
            return Err(TransportFault::Unavailable(AccountUnavailable::Account));
        }
        self.credential_readiness(account)
    }

    fn read_window(
        &self,
        lease: &ScopedCredentialLease,
        window: &CalendarWindow,
        now: time::OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, TransportFault> {
        let start = time::OffsetDateTime::parse(
            window.start.trim(),
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| Protocol(MSG_WINDOW))?;
        let end = time::OffsetDateTime::parse(
            window.end.trim(),
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| Protocol(MSG_WINDOW))?;
        if end <= start || (end - start).whole_days() > MAX_WINDOW_DAYS {
            return Err(Protocol(MSG_WINDOW));
        }
        // This provider serves exactly its configured account.
        if window.account != self.config.account {
            return Err(TransportFault::Refused(MSG_LEASE_REFUSED));
        }
        let collection = self.config.collection_url()?;
        let auth = self.caldav_auth(lease, CALENDAR_READ_OPERATION, now)?;
        let body = calendar_query_report(&ics_utc(start)?, &ics_utc(end)?);
        let response = self.caldav_http.dispatch(CaldavHttpRequest {
            method: "REPORT",
            url: collection,
            auth,
            depth: Some("1"),
            content_type: Some("application/xml"),
            body: Some(body.into_bytes()),
            destination: None,
            if_match: None,
            if_none_match: false,
        })?;
        if response.status != 207 {
            return Err(Protocol(MSG_CALDAV_STATUS));
        }
        let items = parse_multistatus(&response.body)?;
        let mut summaries = Vec::with_capacity(items.len());
        for item in items {
            // Container responses (the collection itself) carry no
            // calendar-data and are skipped, never invented.
            let Some(data) = item.calendar_data else {
                continue;
            };
            let lines = unfold_ics(&String::from_utf8(data).map_err(|_| Protocol(MSG_ICS))?)?;
            for block in vevent_blocks(&lines) {
                let event = parse_ics(block)?;
                let (dtstart, dtend) = match (event.dtstart, event.dtend) {
                    (Some(start), Some(end)) => (start, end),
                    // A time local to an unknown zone is never guessed
                    // as UTC: the event is honestly absent from this UTC
                    // window read instead of aborting the whole calendar.
                    _ if event.zoned => {
                        tracing::warn!(
                            account = %self.config.account,
                            uid = %event.uid,
                            "odin-hermes: calendar event skipped account={} uid={} reason=unknown-zone",
                            self.config.account, event.uid
                        );
                        continue;
                    }
                    _ => return Err(Protocol(MSG_ICS)),
                };
                // A series the server did not expand reports its first
                // meeting: only an instance inside the window is one.
                if dtend <= start || dtstart >= end {
                    continue;
                }
                if event.uid.chars().count() > MAX_EVENT_ID_CHARS {
                    return Err(Protocol(MSG_BOUND));
                }
                summaries.push(CalendarEventSummary {
                    id: event.uid,
                    title: event
                        .summary
                        .map(|value| bounded_chars(&value, MAX_TITLE_CHARS)),
                    start: rfc3339_utc(dtstart)?,
                    end: rfc3339_utc(dtend)?,
                    description: event
                        .description
                        .map(|value| bounded_chars(&value, MAX_EVENT_DESCRIPTION_CHARS)),
                });
            }
        }
        // Expanded series can outnumber the read bound: the earliest
        // meetings are kept.
        summaries.sort_by(|a, b| a.start.cmp(&b.start));
        summaries.truncate(MAX_EVENTS);
        Ok(summaries)
    }

    fn apply(
        &self,
        lease: &ScopedCredentialLease,
        proposal: &CalendarProposal,
        now: time::OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault> {
        // This provider serves exactly its configured account.
        if proposal.account != self.config.account {
            return Err(TransportFault::Refused(MSG_LEASE_REFUSED).into());
        }
        let collection = self.config.collection_url()?;
        let auth = self.caldav_auth(lease, CALENDAR_PROPOSE_OPERATION, now)?;
        let mut event_ids: Vec<String> = Vec::new();
        match &proposal.mutation {
            CalendarMutation::Create(draft) => {
                let (uid, url, body) = self.prepare_new_event(&collection, draft, now)?;
                self.put_new_event(&url, &auth, &body)?;
                event_ids.push(uid);
            }
            CalendarMutation::BatchCreate { drafts } => {
                if drafts.is_empty() || drafts.len() > MAX_BATCH_EVENTS {
                    return Err(Protocol(MSG_BOUND).into());
                }
                // Every draft is rendered and validated before the
                // first PUT: a partial batch can only ever come from a
                // post-commit fault, never from a bad draft. Only the
                // UIDs of acknowledged PUTs are known applied.
                let mut prepared = Vec::with_capacity(drafts.len());
                for draft in drafts {
                    prepared.push(self.prepare_new_event(&collection, draft, now)?);
                }
                for (uid, url, body) in prepared {
                    self.put_new_event(&url, &auth, &body).map_err(|fault| {
                        BatchFault::after(std::mem::take(&mut event_ids), fault)
                    })?;
                    event_ids.push(uid);
                }
            }
            CalendarMutation::Move {
                event_id,
                start,
                end,
            } => {
                validate_event_id(event_id)?;
                let start_at = parse_rfc3339_whole(start)?;
                let end_at = parse_rfc3339_whole(end)?;
                if end_at <= start_at || (end_at - start_at).whole_days() > MAX_WINDOW_DAYS {
                    return Err(Protocol(MSG_PROPOSAL).into());
                }
                let url = self.event_url(&collection, event_id)?;
                let (mut lines, etag) = self.fetch_event_lines(&url, &auth)?;
                let event = parse_ics(&lines)?;
                ensure_ics_uid(&event, event_id)?;
                if event.zoned {
                    // Relocating would have to rewrite a
                    // timezone-local time as UTC, erasing its zone
                    // identity: refused instead of guessed.
                    return Err(Protocol(MSG_ICS_TZ).into());
                }
                set_ics_property(&mut lines, "DTSTART", &ics_utc(start_at)?);
                set_ics_property(&mut lines, "DTEND", &ics_utc(end_at)?);
                set_ics_property(&mut lines, "DTSTAMP", &ics_utc(now)?);
                bump_ics_sequence(&mut lines);
                self.put_event_lines(&url, &auth, &lines, &etag)?;
                event_ids.push(event_id.clone());
            }
            CalendarMutation::Cancel { event_id } => {
                validate_event_id(event_id)?;
                let url = self.event_url(&collection, event_id)?;
                let (mut lines, etag) = self.fetch_event_lines(&url, &auth)?;
                let event = parse_ics(&lines)?;
                ensure_ics_uid(&event, event_id)?;
                // Cancellation rewrites status and revision only: the
                // event's lines — its timezone identity included —
                // stay untouched.
                set_ics_property(&mut lines, "STATUS", "CANCELLED");
                set_ics_property(&mut lines, "DTSTAMP", &ics_utc(now)?);
                bump_ics_sequence(&mut lines);
                self.put_event_lines(&url, &auth, &lines, &etag)?;
                event_ids.push(event_id.clone());
            }
        }
        Ok(CalendarMutationReceipt { event_ids })
    }
}
