//! Gmail API v1 and Google Calendar API v3 transports with explicit account configuration.
//!
//! Tokens use a private `0600` file, atomic refresh writes, and redacted nonserializable wrappers.
//! Requests recheck lease scope and credential handle, never follow redirects, and cap response bytes.
//! Operations use login-granted scopes and are not retried. Calendar cancellation changes status,
//! never deletes the event; public results omit content.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::OpaqueCredentialHandle;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use url::Url;

use crate::account::{
    AccountSecretRef, AccountUnavailable, BatchFault, ScopedCredentialLease, TransportFault,
};
use crate::calendar::{
    CalendarEventSummary, CalendarMutation, CalendarMutationReceipt, CalendarProposal,
    CalendarTransport, CalendarWindow, CALENDAR_PROPOSE_OPERATION, CALENDAR_READ_OPERATION,
    MAX_BATCH_EVENTS, MAX_EVENTS, MAX_EVENT_DESCRIPTION_CHARS, MAX_EVENT_ID_CHARS,
    MAX_LOCATION_CHARS, MAX_TIMESTAMP_CHARS, MAX_TITLE_CHARS, MAX_WINDOW_DAYS,
};
use crate::email::EmailTransport;
use crate::provider::LifeProvider;

/// The provider id every [`GoogleTokenFile`] must declare.
pub const GOOGLE_TOKEN_PROVIDER: &str = "google";

/// The documented Google OAuth2 token endpoint (deployment-rendered).
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The documented Gmail API v1 root (deployment-rendered).
pub const GOOGLE_GMAIL_API_URL: &str = "https://gmail.googleapis.com/gmail/v1";

/// The documented Google Calendar API v3 root (deployment-rendered).
pub const GOOGLE_CALENDAR_API_URL: &str = "https://www.googleapis.com/calendar/v3";

/// Consent scope for `email.search` / `email.read`.
pub const GOOGLE_SCOPE_GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
/// Consent scope for `email.draft`.
pub const GOOGLE_SCOPE_GMAIL_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";
/// Consent scope for `email.send`.
pub const GOOGLE_SCOPE_GMAIL_SEND: &str = "https://www.googleapis.com/auth/gmail.send";
/// Consent scope for label/archive/trash mailbox management.
pub const GOOGLE_SCOPE_GMAIL_MODIFY: &str = "https://www.googleapis.com/auth/gmail.modify";
/// Consent scope for calendar window reads and create/move/cancel.
pub const GOOGLE_SCOPE_CALENDAR_EVENTS: &str = "https://www.googleapis.com/auth/calendar.events";

/// Hard response-byte ceiling when the deployment does not tighten it.
pub const GOOGLE_MAX_RESPONSE_BYTES: u64 = 8_388_608;
/// Per-call wall-clock ceiling in milliseconds when the deployment does
/// not tighten it.
pub const GOOGLE_MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;

/// Most MIME nodes one message payload tree may contain.
pub const MAX_MIME_PARTS: usize = 200;
/// Deepest MIME nesting accepted in one message payload tree.
pub const MAX_MIME_DEPTH: usize = 12;
/// Longest one OAuth2 client id in the token file.
pub const MAX_TOKEN_CLIENT_CHARS: usize = 256;
/// Longest one token value (refresh or access) in the token file.
pub const MAX_TOKEN_VALUE_CHARS: usize = 8_192;
/// Longest one attachment filename recognized (metadata only).
pub const MAX_ATTACHMENT_NAME_CHARS: usize = 256;
/// Access tokens younger than this skew above expiry are refreshed.
const REFRESH_SKEW_SECONDS: i64 = 60;

const MSG_CLIENT: &str = "the Google HTTP client could not be initialized";
const MSG_CONFIG: &str = "the Google account configuration is incomplete";
const MSG_URL: &str = "the configured Google URL is not HTTPS";
const MSG_REDIRECT: &str = "the Google service attempted a redirect, which is disabled";
const MSG_BODY: &str = "the Google response failed its byte bound";
const MSG_BODY_READ: &str = "the Google response body could not be read";
const MSG_EXCHANGE_LOST: &str = "the Google exchange failed after the request may have been sent";
const MSG_PARSE: &str = "the Google response was not the expected shape";
const MSG_REJECTED: &str = "the Google API rejected the request";
const MSG_TOKEN_REJECTED: &str = "the Google token endpoint rejected the refresh";
const MSG_LEASE_REFUSED: &str = "the credential lease does not bind this operation";
const MSG_LEASE_DEPLOYMENT: &str = "the credential lease does not bind this deployment";
const MSG_NOT_FOUND: &str = "the Google resource named by the request was not found";
const MSG_INPUT: &str = "the request is out of bounds";
const MSG_TOKEN_EXPIRY: &str = "the Google token file expiry is not RFC 3339";
const MSG_TOKEN_WRITE: &str = "the Google token file could not be written privately";
const MSG_TOKEN_FILE_SHAPE: &str = "the Google token file has an invalid shape";
const MSG_TOKEN_FILE_PRIVATE: &str = "the Google token file is not a private regular file";
const MSG_TOKEN_SHAPE: &str = "the Google token response was not the expected shape";

/// The exact private token-file schema this provider consumes and the
/// login slice writes: JSON, mode 0600, absolute path, fields
/// `provider` / `client` / `secret` / `refresh` / `access` / `expiry`.
/// Unknown fields are refused so the schema cannot silently drift.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleTokenFile {
    /// The provider id; must be [`GOOGLE_TOKEN_PROVIDER`].
    pub provider: String,
    /// The OAuth2 client id the refresh grant presents.
    pub client: String,
    /// The OAuth2 client secret (the downloaded Desktop-client JSON is
    /// private input). A secret: redacted in `Debug`.
    pub secret: String,
    /// The long-lived refresh grant. A secret: redacted in `Debug`.
    pub refresh: String,
    /// The current access token. A secret: redacted in `Debug`.
    pub access: String,
    /// The access token's expiry, RFC 3339 UTC.
    pub expiry: String,
}

impl GoogleTokenFile {
    /// Builds a token file record with validated bounds and a
    /// canonical RFC 3339 UTC expiry, ready for [`Self::write_private`].
    pub fn new(
        client: &str,
        secret: &str,
        refresh: &str,
        access: &str,
        expiry: OffsetDateTime,
    ) -> Result<Self, TransportFault> {
        let bounded = |value: &str, max: usize| {
            if value.is_empty() || value.chars().count() > max {
                Err(TransportFault::Protocol(MSG_TOKEN_FILE_SHAPE))
            } else {
                Ok(value.to_owned())
            }
        };
        Ok(Self {
            provider: GOOGLE_TOKEN_PROVIDER.to_owned(),
            client: bounded(client, MAX_TOKEN_CLIENT_CHARS)?,
            secret: bounded(secret, MAX_TOKEN_VALUE_CHARS)?,
            refresh: bounded(refresh, MAX_TOKEN_VALUE_CHARS)?,
            access: bounded(access, MAX_TOKEN_VALUE_CHARS)?,
            expiry: Self::render_expiry(expiry)?,
        })
    }

    /// Loads and validates the private token file: a regular file at
    /// mode 0600 carrying exactly this schema for this provider.
    pub fn load(path: &Path) -> Result<Self, TransportFault> {
        check_private(path)?;
        let bytes = std::fs::read(path)
            .map_err(|_| TransportFault::Unavailable(AccountUnavailable::Credentials))?;
        let file: Self = serde_json::from_slice(&bytes)
            .map_err(|_| TransportFault::Protocol(MSG_TOKEN_FILE_SHAPE))?;
        if file.provider != GOOGLE_TOKEN_PROVIDER {
            return Err(TransportFault::Protocol(MSG_TOKEN_FILE_SHAPE));
        }
        Self::new(
            &file.client,
            &file.secret,
            &file.refresh,
            &file.access,
            file.expiry_instant()?,
        )
    }

    /// Writes this record as private state: a mode-0600 file, created
    /// fresh and atomically renamed over `path` so a reader never
    /// observes a torn document.
    pub fn write_private(&self, path: &Path) -> Result<(), TransportFault> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(TransportFault::Protocol(MSG_TOKEN_FILE_PRIVATE))?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or(TransportFault::Protocol(MSG_TOKEN_FILE_PRIVATE))?;
        let temp = parent.join(format!(
            ".{name}.new-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().nanosecond()
        ));
        let body = serde_json::to_vec_pretty(self)
            .map_err(|_| TransportFault::Protocol(MSG_TOKEN_FILE_SHAPE))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| TransportFault::Protocol(MSG_TOKEN_WRITE))?;
        use std::io::Write;
        if file
            .write_all(&body)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(TransportFault::Protocol(MSG_TOKEN_WRITE));
        }
        drop(file);
        if std::fs::rename(&temp, path).is_err() {
            let _ = std::fs::remove_file(&temp);
            return Err(TransportFault::Protocol(MSG_TOKEN_WRITE));
        }
        Ok(())
    }

    /// The parsed expiry instant of the current access token.
    pub fn expiry_instant(&self) -> Result<OffsetDateTime, TransportFault> {
        OffsetDateTime::parse(self.expiry.trim(), &Rfc3339)
            .map(|instant| instant.to_offset(UtcOffset::UTC))
            .map_err(|_| TransportFault::Protocol(MSG_TOKEN_EXPIRY))
    }

    /// The record with a refreshed access token and expiry; the
    /// provider id, client id/secret, and refresh grant are preserved.
    pub fn refreshed(
        self,
        access: &str,
        expires_in_seconds: i64,
        now: OffsetDateTime,
    ) -> Result<Self, TransportFault> {
        Self::new(
            &self.client,
            &self.secret,
            &self.refresh,
            access,
            now + time::Duration::seconds(expires_in_seconds),
        )
    }

    fn render_expiry(expiry: OffsetDateTime) -> Result<String, TransportFault> {
        expiry
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|_| TransportFault::Protocol(MSG_TOKEN_EXPIRY))
    }
}

impl fmt::Debug for GoogleTokenFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleTokenFile")
            .field("provider", &self.provider)
            .field("client", &self.client)
            .field("secret", &"[REDACTED]")
            .field("refresh", &"[REDACTED]")
            .field("access", &"[REDACTED]")
            .field("expiry", &self.expiry)
            .finish()
    }
}

/// The OAuth2 installed/Desktop client credentials parsed from the
/// downloaded Google client JSON (`{"installed": {"client_id": …,
/// "client_secret": …}}`). Private input: the secrets never enter
/// configuration; `Debug` redacts both values and the type never
/// serializes.
#[derive(Clone)]
pub struct GoogleInstalledClient {
    /// The OAuth2 client id.
    pub client_id: String,
    /// The OAuth2 client secret. Redacted in `Debug`.
    pub client_secret: String,
}

impl GoogleInstalledClient {
    /// Reads the required Desktop-client fields, ignoring others and enforcing token-file limits.
    pub fn from_installed_json(raw: &str) -> Result<Self, TransportFault> {
        #[derive(Deserialize)]
        struct Installed {
            #[serde(default)]
            client_id: Option<String>,
            #[serde(default)]
            client_secret: Option<String>,
        }
        #[derive(Deserialize)]
        struct Document {
            #[serde(default)]
            installed: Option<Installed>,
        }
        let document: Document =
            serde_json::from_str(raw).map_err(|_| TransportFault::Protocol(MSG_CONFIG))?;
        let installed = document
            .installed
            .ok_or(TransportFault::Protocol(MSG_CONFIG))?;
        let bounded = |value: Option<String>, max: usize| {
            value
                .filter(|value| !value.is_empty() && value.chars().count() <= max)
                .ok_or(TransportFault::Protocol(MSG_CONFIG))
        };
        Ok(Self {
            client_id: bounded(installed.client_id, MAX_TOKEN_CLIENT_CHARS)?,
            client_secret: bounded(installed.client_secret, MAX_TOKEN_VALUE_CHARS)?,
        })
    }

    /// Builds the self-contained private token file record this
    /// provider consumes from a completed consent grant.
    pub fn token_file(
        &self,
        refresh: &str,
        access: &str,
        expiry: OffsetDateTime,
    ) -> Result<GoogleTokenFile, TransportFault> {
        GoogleTokenFile::new(
            &self.client_id,
            &self.client_secret,
            refresh,
            access,
            expiry,
        )
    }
}

impl fmt::Debug for GoogleInstalledClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleInstalledClient")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// The private token file must be a regular file at mode 0600; anything
/// else is refused before any secret is read.
fn check_private(path: &Path) -> Result<(), TransportFault> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| TransportFault::Unavailable(AccountUnavailable::Credentials))?;
    if !metadata.is_file() {
        return Err(TransportFault::Protocol(MSG_TOKEN_FILE_PRIVATE));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 {
            return Err(TransportFault::Protocol(MSG_TOKEN_FILE_PRIVATE));
        }
    }
    Ok(())
}

/// One HTTP call against a documented Google endpoint. `bearer` is the
/// access token; `form` is the token-endpoint grant body (which carries
/// secrets and is redacted in `Debug`). The `url` carries no credential
/// material.
#[derive(Clone)]
pub struct GoogleRequest {
    pub method: GoogleMethod,
    pub url: String,
    pub bearer: Option<String>,
    pub json: Option<Value>,
    pub form: Vec<(String, String)>,
}

impl fmt::Debug for GoogleRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("bearer", &"[REDACTED]")
            .field("json", &self.json)
            .field("form", &"[REDACTED]")
            .finish()
    }
}

/// The HTTP methods the Google wire uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleMethod {
    Get,
    Post,
    Patch,
}

/// One bounded Google API response: status plus the parsed JSON body
/// (empty bodies parse as null). Upstream body text never leaves this
/// value: faults are static, so `body` must never be embedded in one.
#[derive(Clone, Debug)]
pub struct GoogleResponse {
    pub status: u16,
    pub body: Value,
}

/// Reports unavailable only before dispatch; timeouts and protocol failures leave the outcome uncertain.
pub trait GoogleWire: Send + Sync {
    fn call(&self, request: GoogleRequest) -> Result<GoogleResponse, TransportFault>;
}

/// The production HTTPS wire: `reqwest::blocking`, redirects disabled,
/// one bounded call per exchange. Built for the one-shot supervised
/// adapter process — never call it from inside a Tokio runtime without
/// `spawn_blocking`.
pub struct HttpsGoogleWire {
    request_timeout: Duration,
    max_response_bytes: u64,
}

impl HttpsGoogleWire {
    pub fn new(request_timeout_ms: u64, max_response_bytes: u64) -> Self {
        Self {
            request_timeout: Duration::from_millis(
                request_timeout_ms.clamp(1, GOOGLE_MAX_REQUEST_TIMEOUT_MS),
            ),
            max_response_bytes: max_response_bytes.clamp(1_024, GOOGLE_MAX_RESPONSE_BYTES),
        }
    }
}

impl GoogleWire for HttpsGoogleWire {
    fn call(&self, request: GoogleRequest) -> Result<GoogleResponse, TransportFault> {
        // Redirects stay disabled on the shared client: any 3xx is a typed fault below.
        let client =
            crate::http_pool::no_redirect().map_err(|_| TransportFault::Protocol(MSG_CLIENT))?;
        let mut call = match request.method {
            GoogleMethod::Get => client.get(&request.url),
            GoogleMethod::Post => client.post(&request.url),
            GoogleMethod::Patch => client.patch(&request.url),
        };
        call = call.timeout(self.request_timeout);
        if let Some(bearer) = &request.bearer {
            call = call.bearer_auth(bearer);
        }
        if !request.form.is_empty() {
            call = call.form(&request.form);
        }
        if let Some(json) = &request.json {
            call = call.json(json);
        } else if matches!(request.method, GoogleMethod::Post) && request.form.is_empty() {
            // A bodiless POST leaves without Content-Length and Google's
            // front end answers 411 with an HTML page (10-03: every "move to
            // the trash" failed as "not the expected shape").
            call = call.header(reqwest::header::CONTENT_LENGTH, "0");
        }
        let response = call.send().map_err(map_request_error)?;
        let status = response.status();
        // A refusal's body is often an HTML page: name it a refusal, not a
        // shape fault.
        let body = match read_bounded(response, self.max_response_bytes) {
            Err(TransportFault::Protocol(MSG_PARSE)) if !status.is_success() => {
                tracing::error!(
                    status = status.as_u16(),
                    "odin-hermes: google refused status={} (non-JSON body)",
                    status.as_u16()
                );
                return Err(TransportFault::ProtocolDetail {
                    message: MSG_REJECTED,
                    status: status.as_u16(),
                });
            }
            other => other?,
        };
        Ok(GoogleResponse {
            status: status.as_u16(),
            body,
        })
    }
}

/// Reads one response body under the hard byte ceiling: chunked or
/// length-less bodies are cut off at `max + 1` bytes instead of
/// buffered whole before the check. An empty body is a null document.
fn read_bounded(
    response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<Value, TransportFault> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let mut reader = response.take(max_bytes.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| TransportFault::Protocol(MSG_BODY_READ))?;
    if bytes.len() as u64 > max_bytes {
        return Err(TransportFault::Protocol(MSG_BODY));
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|_| TransportFault::Protocol(MSG_PARSE))
}

/// Only connection and request-build failures guarantee nothing was sent; other failures stay uncertain.
fn map_request_error(error: reqwest::Error) -> TransportFault {
    if error.is_timeout() {
        return TransportFault::Timeout;
    }
    if error.is_redirect() {
        return TransportFault::Protocol(MSG_REDIRECT);
    }
    if error.is_connect() || error.is_builder() {
        return TransportFault::Unavailable(AccountUnavailable::Service);
    }
    if error.is_body() || error.is_decode() {
        return TransportFault::Protocol(MSG_BODY_READ);
    }
    TransportFault::Protocol(MSG_EXCHANGE_LOST)
}

/// A resolved access token. The value is readable only inside the
/// provider's request-building frames; `Debug` redacts and the type
/// never serializes.
#[derive(Clone)]
struct AccessToken(String);

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

/// The in-process cache of the current access token so repeated
/// exchanges inside one window do not re-read or re-refresh the file.
#[derive(Clone)]
struct CachedToken {
    access: AccessToken,
    expires_at: OffsetDateTime,
}

/// Deployment facts of one Google account, all rendered from
/// Nix/dotfiles configuration. No field has a default; the documented
/// endpoint constants exist for the renderer to copy.
#[derive(Clone)]
pub struct GoogleAccountConfig {
    /// The life account selector this deployment binds.
    pub account: String,
    /// The credential reference: opaque handle + absolute 0600 token
    /// file path ([`GoogleTokenFile`] schema).
    pub credential: AccountSecretRef,
    /// The OAuth2 token endpoint (see [`GOOGLE_TOKEN_URL`]); HTTPS.
    pub token_url: String,
    /// The Gmail API v1 root (see [`GOOGLE_GMAIL_API_URL`]); HTTPS.
    pub gmail_api_url: String,
    /// The Calendar API v3 root (see [`GOOGLE_CALENDAR_API_URL`]); HTTPS.
    pub calendar_api_url: String,
    /// The calendar id all calendar operations address (e.g. primary).
    pub calendar_id: String,
    /// Per-call deadline in milliseconds.
    pub request_timeout_ms: u64,
    /// Hard response-byte ceiling.
    pub max_response_bytes: u64,
}

impl GoogleAccountConfig {
    /// Validates and bounds the configured facts.
    pub fn validated(self) -> Result<Self, TransportFault> {
        use crate::account::MAX_ACCOUNT_CHARS;
        for url in [&self.token_url, &self.gmail_api_url, &self.calendar_api_url] {
            if !url.starts_with("https://") {
                return Err(TransportFault::Protocol(MSG_URL));
            }
        }
        if self.account.trim().is_empty()
            || self.account.chars().count() > MAX_ACCOUNT_CHARS
            || self.calendar_id.trim().is_empty()
            || self.calendar_id.chars().count() > MAX_EVENT_ID_CHARS
        {
            return Err(TransportFault::Protocol(MSG_CONFIG));
        }
        Ok(self)
    }
}

impl fmt::Debug for GoogleAccountConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAccountConfig")
            .field("account", &self.account)
            .field("credential", &self.credential)
            .field("token_url", &self.token_url)
            .field("gmail_api_url", &self.gmail_api_url)
            .field("calendar_api_url", &self.calendar_api_url)
            .field("calendar_id", &self.calendar_id)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// The production Google provider: real Gmail + Calendar REST over the
/// wire seam, one private 0600 token file, typed faults only. It serves
/// both transport ports and the [`LifeProvider`] port for exactly its
/// configured account.
#[derive(Clone)]
pub struct GoogleProvider {
    config: GoogleAccountConfig,
    wire: Arc<dyn GoogleWire>,
    token: Arc<parking_lot::Mutex<Option<CachedToken>>>,
}

impl fmt::Debug for GoogleProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleProvider")
            .field("config", &self.config)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl GoogleProvider {
    /// Builds the provider over the given wire seam. Production passes
    /// [`HttpsGoogleWire`]; tests script the seam.
    pub fn new(
        config: GoogleAccountConfig,
        wire: Arc<dyn GoogleWire>,
    ) -> Result<Self, TransportFault> {
        Ok(Self {
            config: config.validated()?,
            wire,
            token: Arc::new(parking_lot::Mutex::new(None)),
        })
    }

    /// The account selector this provider serves.
    pub fn account(&self) -> &str {
        &self.config.account
    }

    /// Rechecks capability, account, expiry, and configured credential handle before sending.
    fn check_lease(
        &self,
        lease: &ScopedCredentialLease,
        operation: &'static str,
        account: &str,
        now: OffsetDateTime,
    ) -> Result<(), TransportFault> {
        use odin_domain::CapabilityId;
        let capability =
            CapabilityId::new(operation).expect("the reserved life capability id is valid");
        lease
            .admits(&capability, account, now)
            .map_err(|_| TransportFault::Refused(MSG_LEASE_REFUSED))?;
        let handle: OpaqueCredentialHandle = self.config.credential.handle().clone();
        if !lease.binds_handle(&handle) {
            return Err(TransportFault::Refused(MSG_LEASE_DEPLOYMENT));
        }
        Ok(())
    }

    /// The current access token: cache hit, valid token file, or one
    /// refresh grant exchange with an atomic private write-back.
    fn access_token(&self, now: OffsetDateTime) -> Result<AccessToken, TransportFault> {
        {
            let cached = self.token.lock();
            if let Some(hit) = cached.as_ref() {
                if hit.expires_at - now > time::Duration::seconds(REFRESH_SKEW_SECONDS) {
                    return Ok(hit.access.clone());
                }
            }
        }
        let file = GoogleTokenFile::load(self.config.credential.secret_path())?;
        let expiry = file.expiry_instant()?;
        if expiry - now > time::Duration::seconds(REFRESH_SKEW_SECONDS) {
            let hit = CachedToken {
                access: AccessToken(file.access.clone()),
                expires_at: expiry,
            };
            let access = hit.access.clone();
            *self.token.lock() = Some(hit);
            return Ok(access);
        }
        let response = self.wire.call(GoogleRequest {
            method: GoogleMethod::Post,
            url: self.config.token_url.clone(),
            bearer: None,
            json: None,
            form: vec![
                ("grant_type".to_owned(), "refresh_token".to_owned()),
                ("refresh_token".to_owned(), file.refresh.clone()),
                ("client_id".to_owned(), file.client.clone()),
                ("client_secret".to_owned(), file.secret.clone()),
            ],
        })?;
        match response.status {
            200 => {}
            // An invalid grant or client is a typed credential fault.
            400 | 401 | 403 => {
                return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
            }
            _ => return Err(TransportFault::Protocol(MSG_TOKEN_REJECTED)),
        }
        let access = response
            .body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty() && token.chars().count() <= MAX_TOKEN_VALUE_CHARS)
            .ok_or(TransportFault::Protocol(MSG_TOKEN_SHAPE))?
            .to_owned();
        let expires_in = response
            .body
            .get("expires_in")
            .and_then(Value::as_i64)
            .filter(|seconds| (1..=86_400).contains(seconds))
            .ok_or(TransportFault::Protocol(MSG_TOKEN_SHAPE))?;
        let updated = file.refreshed(&access, expires_in, now)?;
        let expires_at = updated.expiry_instant()?;
        updated.write_private(self.config.credential.secret_path())?;
        let hit = CachedToken {
            access: AccessToken(access),
            expires_at,
        };
        let access_token = hit.access.clone();
        *self.token.lock() = Some(hit);
        Ok(access_token)
    }

    /// Builds an absolute Calendar API URL from path segments and
    /// query pairs, percent-encoding each segment.
    fn calendar_url(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<String, TransportFault> {
        self.build_url(&self.config.calendar_api_url, segments, query)
    }

    fn build_url(
        &self,
        root: &str,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<String, TransportFault> {
        let mut url = Url::parse(root).map_err(|_| TransportFault::Protocol(MSG_CONFIG))?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| TransportFault::Protocol(MSG_CONFIG))?;
            path.extend(segments.iter());
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url.into())
    }

    /// Sends one API call with the current access token.
    fn call(
        &self,
        method: GoogleMethod,
        url: String,
        json: Option<Value>,
        access: &AccessToken,
    ) -> Result<GoogleResponse, TransportFault> {
        self.wire.call(GoogleRequest {
            method,
            url,
            bearer: Some(access.0.clone()),
            json,
            form: Vec::new(),
        })
    }
}

/// A bounded non-empty upstream id.
fn required_id(value: Option<&Value>, max: usize) -> Result<String, TransportFault> {
    match value {
        Some(Value::String(id)) if !id.is_empty() && id.chars().count() <= max => Ok(id.clone()),
        _ => Err(TransportFault::Protocol(MSG_PARSE)),
    }
}

/// A bounded optional upstream string field.
fn bounded_text(value: Option<&Value>, max: usize) -> Result<Option<String>, TransportFault> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.chars().count() <= max => Ok(Some(text.clone())),
        Some(Value::String(_)) => Err(TransportFault::Protocol(MSG_BODY)),
        Some(_) => Err(TransportFault::Protocol(MSG_PARSE)),
    }
}

/// Revalidates event limits at the wire boundary.
fn validate_draft(draft: &crate::calendar::CalendarEventDraft) -> Result<(), TransportFault> {
    let title = draft.title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE_CHARS {
        return Err(TransportFault::Protocol(MSG_INPUT));
    }
    let start = OffsetDateTime::parse(draft.start.trim(), &Rfc3339)
        .map_err(|_| TransportFault::Protocol(MSG_INPUT))?;
    let end = OffsetDateTime::parse(draft.end.trim(), &Rfc3339)
        .map_err(|_| TransportFault::Protocol(MSG_INPUT))?;
    if end <= start || (end - start).whole_days() > MAX_WINDOW_DAYS {
        return Err(TransportFault::Protocol(MSG_INPUT));
    }
    if let Some(location) = &draft.location {
        if location.chars().count() > MAX_LOCATION_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
    }
    if let Some(description) = &draft.description {
        if description.chars().count() > MAX_EVENT_DESCRIPTION_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
    }
    Ok(())
}

/// The event resource body for one bounded draft.
fn event_body(draft: &crate::calendar::CalendarEventDraft) -> Value {
    let mut event = serde_json::json!({
        "summary": draft.title.trim(),
        "start": { "dateTime": draft.start.trim() },
        "end": { "dateTime": draft.end.trim() },
    });
    if let Some(location) = draft.location.as_deref().map(str::trim) {
        event["location"] = Value::String(location.to_owned());
    }
    if let Some(description) = draft.description.as_deref().map(str::trim) {
        event["description"] = Value::String(description.to_owned());
    }
    event
}

/// One sanitized bounded calendar event from a Calendar API item.
fn parse_event(item: &Value) -> Result<CalendarEventSummary, TransportFault> {
    let instant = |holder: &Value| {
        let value = holder
            .get("dateTime")
            .or_else(|| holder.get("date"))
            .and_then(Value::as_str);
        match value {
            Some(text) if text.chars().count() <= MAX_TIMESTAMP_CHARS => Ok(text.to_owned()),
            _ => Err(TransportFault::Protocol(MSG_BODY)),
        }
    };
    let start = item
        .get("start")
        .ok_or(TransportFault::Protocol(MSG_PARSE))
        .and_then(instant)?;
    let end = item
        .get("end")
        .ok_or(TransportFault::Protocol(MSG_PARSE))
        .and_then(instant)?;
    Ok(CalendarEventSummary {
        id: required_id(item.get("id"), MAX_EVENT_ID_CHARS)?,
        title: bounded_text(item.get("summary"), MAX_TITLE_CHARS)?,
        start,
        end,
        description: bounded_text(item.get("description"), MAX_EVENT_DESCRIPTION_CHARS)?,
    })
}

mod mail;

impl CalendarTransport for GoogleProvider {
    fn readiness(&self, account: &str) -> Result<(), TransportFault> {
        self.token_readiness(account)
    }

    fn read_window(
        &self,
        lease: &ScopedCredentialLease,
        window: &CalendarWindow,
        now: OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, TransportFault> {
        self.check_lease(lease, CALENDAR_READ_OPERATION, &window.account, now)?;
        // Reparse timestamps so malformed input never becomes a malformed URL.
        let start = OffsetDateTime::parse(window.start.trim(), &Rfc3339)
            .map_err(|_| TransportFault::Protocol(MSG_INPUT))?;
        let end = OffsetDateTime::parse(window.end.trim(), &Rfc3339)
            .map_err(|_| TransportFault::Protocol(MSG_INPUT))?;
        if end <= start {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        let access = self.access_token(now)?;
        let mut events = Vec::new();
        let mut page_token = String::new();
        loop {
            let max_results = MAX_EVENTS.to_string();
            let mut query = vec![
                ("timeMin", window.start.trim()),
                ("timeMax", window.end.trim()),
                ("singleEvents", "true"),
                ("orderBy", "startTime"),
                ("showDeleted", "false"),
                ("maxResults", max_results.as_str()),
            ];
            if !page_token.is_empty() {
                query.push(("pageToken", page_token.as_str()));
            }
            let url =
                self.calendar_url(&["calendars", &self.config.calendar_id, "events"], &query)?;
            let response = self.call(GoogleMethod::Get, url, None, &access)?;
            if response.status != 200 {
                return Err(TransportFault::ProtocolDetail {
                    message: MSG_REJECTED,
                    status: response.status,
                });
            }
            let items = response
                .body
                .get("items")
                .and_then(Value::as_array)
                .ok_or(TransportFault::Protocol(MSG_PARSE))?;
            for item in items {
                events.push(parse_event(item)?);
            }
            if events.len() > MAX_EVENTS {
                return Err(TransportFault::Protocol(MSG_BODY));
            }
            match response.body.get("nextPageToken").and_then(Value::as_str) {
                Some(token) if !token.is_empty() => page_token = token.to_owned(),
                _ => break,
            }
        }
        Ok(events)
    }

    fn apply(
        &self,
        lease: &ScopedCredentialLease,
        proposal: &CalendarProposal,
        now: OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault> {
        self.check_lease(lease, CALENDAR_PROPOSE_OPERATION, &proposal.account, now)?;
        let access = self.effect_access_token(now)?;
        let mut event_ids = Vec::new();
        match &proposal.mutation {
            CalendarMutation::Create(draft) => {
                validate_draft(draft)?;
                event_ids.push(self.create_event(draft, &access)?);
            }
            CalendarMutation::BatchCreate { drafts } => {
                if drafts.is_empty() || drafts.len() > MAX_BATCH_EVENTS {
                    return Err(TransportFault::Protocol(MSG_INPUT).into());
                }
                // The whole batch validates before the first POST: a
                // partial batch only ever follows a member that applied.
                for draft in drafts {
                    validate_draft(draft)?;
                }
                for draft in drafts {
                    let id = self.create_event(draft, &access).map_err(|fault| {
                        BatchFault::after(std::mem::take(&mut event_ids), fault)
                    })?;
                    event_ids.push(id);
                }
            }
            CalendarMutation::Move {
                event_id,
                start,
                end,
            } => {
                // A move is a reschedule: absolute UTC instants.
                self.check_event_id(event_id)?;
                let start_at = OffsetDateTime::parse(start.trim(), &Rfc3339)
                    .map_err(|_| TransportFault::Protocol(MSG_INPUT))?;
                let end_at = OffsetDateTime::parse(end.trim(), &Rfc3339)
                    .map_err(|_| TransportFault::Protocol(MSG_INPUT))?;
                if end_at <= start_at {
                    return Err(TransportFault::Protocol(MSG_INPUT).into());
                }
                let url = self.calendar_url(&self.event_segments(event_id), &[])?;
                let response = self.call(
                    GoogleMethod::Patch,
                    url,
                    Some(serde_json::json!({
                        "start": { "dateTime": start.trim() },
                        "end": { "dateTime": end.trim() },
                    })),
                    &access,
                )?;
                if response.status == 404 {
                    return Err(TransportFault::Protocol(MSG_NOT_FOUND).into());
                }
                if response.status != 200 {
                    return Err(TransportFault::ProtocolDetail {
                        message: MSG_REJECTED,
                        status: response.status,
                    }
                    .into());
                }
                event_ids.push(required_id(response.body.get("id"), MAX_EVENT_ID_CHARS)?);
            }
            CalendarMutation::Cancel { event_id } => {
                // A cancel is the documented status transition: the
                // event is patched to cancelled, never destroyed.
                self.check_event_id(event_id)?;
                let url = self.calendar_url(&self.event_segments(event_id), &[])?;
                let response = self.call(
                    GoogleMethod::Patch,
                    url,
                    Some(serde_json::json!({ "status": "cancelled" })),
                    &access,
                )?;
                if response.status == 404 {
                    return Err(TransportFault::Protocol(MSG_NOT_FOUND).into());
                }
                if response.status != 200 {
                    return Err(TransportFault::ProtocolDetail {
                        message: MSG_REJECTED,
                        status: response.status,
                    }
                    .into());
                }
                // The receipt preserves the cancelled id: the server
                // echo when present, the requested id otherwise.
                match response.body.get("id") {
                    Some(Value::String(id))
                        if !id.is_empty() && id.chars().count() <= MAX_EVENT_ID_CHARS =>
                    {
                        event_ids.push(id.clone());
                    }
                    _ => event_ids.push(event_id.clone()),
                }
            }
        }
        Ok(CalendarMutationReceipt { event_ids })
    }
}

impl GoogleProvider {
    /// Checks account and private token-file readiness without refreshing, requesting, or writing.
    fn token_readiness(&self, account: &str) -> Result<(), TransportFault> {
        if account != self.config.account {
            return Err(TransportFault::Unavailable(AccountUnavailable::Account));
        }
        GoogleTokenFile::load(self.config.credential.secret_path()).map(drop)
    }

    /// The access token a mutation rides. Obtaining it never sends the
    /// mutation, so any fault here (including a lost or refused refresh
    /// exchange) proves the effect itself never dispatched.
    fn effect_access_token(&self, now: OffsetDateTime) -> Result<AccessToken, TransportFault> {
        self.access_token(now).map_err(|fault| match fault {
            TransportFault::Unavailable(_) | TransportFault::Refused(_) => fault,
            TransportFault::Protocol(_)
            | TransportFault::ProtocolDetail { .. }
            | TransportFault::Timeout => {
                TransportFault::Unavailable(AccountUnavailable::Credentials)
            }
        })
    }

    /// Creates one event; its id is known only from a 200 reply.
    fn create_event(
        &self,
        draft: &crate::calendar::CalendarEventDraft,
        access: &AccessToken,
    ) -> Result<String, TransportFault> {
        let url = self.calendar_url(&["calendars", &self.config.calendar_id, "events"], &[])?;
        let response = self.call(GoogleMethod::Post, url, Some(event_body(draft)), access)?;
        if response.status != 200 {
            return Err(TransportFault::ProtocolDetail {
                message: MSG_REJECTED,
                status: response.status,
            });
        }
        required_id(response.body.get("id"), MAX_EVENT_ID_CHARS)
    }

    fn check_event_id(&self, event_id: &str) -> Result<(), TransportFault> {
        if event_id.is_empty() || event_id.chars().count() > MAX_EVENT_ID_CHARS {
            return Err(TransportFault::Protocol(MSG_INPUT));
        }
        Ok(())
    }

    /// The percent-encoded path segments of one event resource.
    fn event_segments<'a>(&'a self, event_id: &'a str) -> [&'a str; 4] {
        [
            "calendars",
            self.config.calendar_id.as_str(),
            "events",
            event_id,
        ]
    }
}

impl LifeProvider for GoogleProvider {
    fn email_transport(&self, account: &str) -> Option<Arc<dyn EmailTransport>> {
        if account == self.config.account {
            Some(Arc::new(self.clone()))
        } else {
            None
        }
    }

    fn calendar_transport(&self, account: &str) -> Option<Arc<dyn CalendarTransport>> {
        if account == self.config.account {
            Some(Arc::new(self.clone()))
        } else {
            None
        }
    }
}
