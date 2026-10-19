//! `odin account` — one-time provider consent capture and private
//! credential binding for life providers.
//!
//! Security constraints:
//!
//! * Every input (account selector, credential path, tenant, downloaded
//!   client document) is validated and bounded before any network call.
//! * Secrets — client secrets, authorization codes, access and refresh
//!   tokens, device codes — are never printed, logged, or carried in an
//!   error: fault text is static. Only Microsoft's user-facing
//!   `user_code` and verification URI are shown, exactly as the
//!   protocol intends.
//! * HTTP redirects are disabled and every response body is
//!   byte-bounded.
//! * Credential files are installed atomically (private temp file,
//!   fsync, rename) at mode 0600 inside a private 0700 parent; a
//!   failed login leaves no partial token.
//! * There is no API-key path: API keys cannot authorize private Gmail
//!   or Calendar data, so only user consent grants are accepted.

use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL_NOPAD;
use base64::Engine as _;
use clap::{Args, Subcommand};
use odin_hermes::account::MAX_ACCOUNT_CHARS;
use odin_hermes::google::{
    GoogleInstalledClient, GOOGLE_SCOPE_CALENDAR_EVENTS, GOOGLE_SCOPE_GMAIL_COMPOSE,
    GOOGLE_SCOPE_GMAIL_MODIFY, GOOGLE_SCOPE_GMAIL_READONLY, GOOGLE_SCOPE_GMAIL_SEND,
    GOOGLE_TOKEN_URL,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

use odin_cli::authority_provision::{hex_string, os_random_bytes};

use crate::RunStatus;

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub(crate) struct AccountArgs {
    #[command(subcommand)]
    command: AccountCommand,
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    /// Capture one-time provider consent into a private credential file.
    Login(LoginArgs),
    /// Bind a separately issued CalDAV app token into an existing credential bundle.
    ConfigureCaldav(CaldavConfigureArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    #[command(subcommand)]
    provider: LoginCommand,
}

#[derive(Debug, Subcommand)]
enum LoginCommand {
    /// Google Gmail + Calendar consent through the installed-app loopback
    /// flow (PKCE S256; no out-of-band fallback).
    Google(GoogleLoginArgs),
    /// Microsoft mail consent through the device-code flow, installing the
    /// credential bundle the generic IMAP/SMTP provider consumes.
    MicrosoftMail(MicrosoftMailLoginArgs),
}

#[derive(Debug, Args)]
pub(crate) struct GoogleLoginArgs {
    /// Life account selector this consent is bound to.
    #[arg(long, value_name = "ID")]
    account: String,
    /// The downloaded Google Desktop client JSON (`{"installed": …}`).
    #[arg(long, value_name = "PATH")]
    client_config: PathBuf,
    /// Absolute path of the private token file to install (mode 0600).
    #[arg(long, value_name = "PATH")]
    token_path: PathBuf,
    /// Request only Google Calendar access. Use this for Workspace identities
    /// whose administrator disables Gmail while leaving Calendar enabled.
    #[arg(long)]
    calendar_only: bool,
}

#[derive(Debug, Args)]
pub(crate) struct MicrosoftMailLoginArgs {
    /// Life account selector; doubles as the XOAUTH2 sign-in user (the
    /// Caltech UPN).
    #[arg(long, value_name = "ID")]
    account: String,
    /// Absolute path of the private credential bundle to install (mode 0600).
    #[arg(long, value_name = "PATH")]
    token_path: PathBuf,
    /// Microsoft tenant: `common`, `organizations`, `consumers`, a tenant
    /// domain, or a tenant UUID.
    #[arg(long, value_name = "TENANT", default_value = "common")]
    tenant: String,
    /// Also run an explicit Calendars.ReadWrite consent probe. The probe
    /// reports granted or refused only; it never configures or ships a
    /// Graph backend and never stores a credential.
    #[arg(long)]
    probe_graph_calendar: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CaldavConfigureArgs {
    /// Life account selector already bound by the credential bundle.
    #[arg(long, value_name = "ID")]
    account: String,
    /// Existing private provider credential bundle to extend in place.
    #[arg(long, value_name = "PATH")]
    token_path: PathBuf,
    /// CalDAV HTTP Basic user id.
    #[arg(long, value_name = "USER")]
    user: String,
    /// Private mode-0600 file containing the CalDAV app token.
    #[arg(long, value_name = "PATH")]
    app_token_path: PathBuf,
}

pub(crate) fn account_command(
    arguments: AccountArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    match arguments.command {
        AccountCommand::Login(arguments) => match arguments.provider {
            LoginCommand::Google(arguments) => login_google(arguments, output),
            LoginCommand::MicrosoftMail(arguments) => login_microsoft_mail(arguments, output),
        },
        AccountCommand::ConfigureCaldav(arguments) => configure_caldav(arguments, output),
    }
}

// ---------------------------------------------------------------------------
// Shared bounds and helpers
// ---------------------------------------------------------------------------

/// Documented Google authorization endpoint (deployment-rendered).
const GOOGLE_AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Consent scopes the Google provider consumes; one consent grant covers
/// Gmail and Calendar for the bound account.
const GOOGLE_SCOPES: &[&str] = &[
    GOOGLE_SCOPE_GMAIL_READONLY,
    GOOGLE_SCOPE_GMAIL_COMPOSE,
    GOOGLE_SCOPE_GMAIL_SEND,
    GOOGLE_SCOPE_GMAIL_MODIFY,
    GOOGLE_SCOPE_CALENDAR_EVENTS,
];
/// Calendar-only consent for Workspace identities without Gmail service.
const GOOGLE_CALENDAR_ONLY_SCOPES: &[&str] = &[GOOGLE_SCOPE_CALENDAR_EVENTS];
/// The downloaded Desktop-client document is tiny; anything larger is
/// refused before parsing.
const GOOGLE_CLIENT_DOCUMENT_MAX_BYTES: u64 = 64 * 1024;
/// Matches the provider's token-file length limit.
const GOOGLE_TOKEN_VALUE_CHARS: usize = 8_192;
/// The consent grant must complete within ten minutes.
const LOOPBACK_BUDGET_SECONDS: u64 = 600;
/// Most loopback callbacks answered before the flow gives up.
const LOOPBACK_MAX_CALLBACKS: usize = 16;
/// Longest one callback request head; longer requests are refused.
const LOOPBACK_HEAD_MAX_BYTES: usize = 16 * 1024;
/// Per-callback read/write deadline.
const LOOPBACK_IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Hard byte ceiling on every token/device endpoint response.
const OAUTH_RESPONSE_MAX_BYTES: u64 = 64 * 1024;
/// Longest one authorization code accepted from the loopback callback.
const AUTH_CODE_MAX_CHARS: usize = 2_048;

/// The public Thunderbird client id: Microsoft mail is a public client
/// (no client secret exists or is stored).
const MICROSOFT_THUNDERBIRD_CLIENT_ID: &str = "9e5f94bc-e8a4-4e73-b8be-63364c29d753";
/// Fully qualified Outlook scopes for IMAP/SMTP plus the offline grant.
const MICROSOFT_MAIL_SCOPE: &str =
    "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access";
/// The direct Graph calendar probe requests exactly one scope.
const MICROSOFT_GRAPH_PROBE_SCOPE: &str = "https://graph.microsoft.com/Calendars.ReadWrite";
/// RFC 8628 device-authorization grant type.
const MICROSOFT_DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Version of the generic IMAP/SMTP credential bundle schema.
const MICROSOFT_MAIL_CREDENTIAL_VERSION: u32 = 1;
/// The generic provider refuses credential files over this size; the
/// token-value bounds below keep the bundle well inside it.
const MICROSOFT_CREDENTIAL_MAX_BYTES: usize = 16 * 1024;
/// Longest one access/refresh value stored in the Microsoft bundle.
const MICROSOFT_TOKEN_VALUE_CHARS: usize = 4_096;
/// Device polling cadence when the endpoint does not name one.
const MICROSOFT_DEFAULT_POLL_SECONDS: u64 = 5;
/// Longest one device polling cadence (also the `slow_down` ceiling).
const MICROSOFT_MAX_POLL_SECONDS: u64 = 60;
/// Hard polling budget regardless of the advertised code lifetime.
const MICROSOFT_POLL_HARD_BUDGET_SECONDS: i64 = 3_600;

const CALLBACK_ACCEPTED_BODY: &str =
    "<html><body><p>Sign-in complete. Return to the terminal.</p></body></html>";
const CALLBACK_DENIED_BODY: &str =
    "<html><body><p>Sign-in was refused. Return to the terminal.</p></body></html>";
const CALLBACK_REFUSED_BODY: &str =
    "<html><body><p>Sign-in could not be completed. Return to the terminal.</p></body></html>";
const REPORT_WRITE_ERROR: &str = "could not write the login report";

fn report(output: &mut impl Write, line: &str) -> Result<(), String> {
    writeln!(output, "{line}").map_err(|_| REPORT_WRITE_ERROR.to_owned())
}

fn login_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Runtime::new()
        .map_err(|error| format!("could not start the login runtime: {error}"))
}

fn validate_account(raw: &str) -> Result<&str, String> {
    if raw.is_empty()
        || raw.chars().count() > MAX_ACCOUNT_CHARS
        || raw != raw.trim()
        || raw.chars().any(char::is_control)
    {
        return Err("the account selector must be 1 to 128 non-control characters without leading or trailing whitespace".to_owned());
    }
    Ok(raw)
}

fn validate_token_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("the credential path must be absolute; relative paths would depend on the process working directory".to_owned());
    }
    if path.file_name().is_none() {
        return Err("the credential path must name a file".to_owned());
    }
    Ok(())
}

fn validate_tenant(raw: &str) -> Result<&str, String> {
    let well_formed = !raw.is_empty()
        && raw.chars().count() <= 64
        && raw
            .chars()
            .next()
            .is_some_and(|char| char.is_ascii_alphanumeric())
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if well_formed {
        Ok(raw)
    } else {
        Err("the tenant must be 1 to 64 ASCII letters, digits, dots, or hyphens and start with a letter or digit".to_owned())
    }
}

/// Ensures the credential file's parent directory exists and is private
/// (mode 0700), before any secret exists to protect.
fn ensure_private_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "the credential path has no parent directory".to_owned())?;
    if parent.exists() {
        let metadata = std::fs::metadata(parent)
            .map_err(|_| "the credential directory could not be inspected".to_owned())?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", parent.display()));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(format!(
                "the credential directory {} must be private (mode 0700)",
                parent.display()
            ));
        }
    } else {
        std::fs::create_dir_all(parent).map_err(|_| {
            format!(
                "the credential directory {} could not be created",
                parent.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|_| {
            format!(
                "the credential directory {} could not be made private",
                parent.display()
            )
        })?;
    }
    Ok(())
}

/// Writes `body` as private state: a mode-0600 file created fresh and
/// atomically renamed over `path`, so a reader never observes a torn
/// document and a failed write leaves no partial credential.
fn write_private_atomic(path: &Path, body: &[u8]) -> Result<(), String> {
    odin_cli::authority_provision::write_private_atomic(path, body).map_err(|error| {
        if error.contains("has no parent directory") {
            "the credential path has no parent directory".to_owned()
        } else if error.contains("is not a plain file name") {
            "the credential path has no file name".to_owned()
        } else if error.contains("could not create the private temporary file") {
            "the private credential file could not be created".to_owned()
        } else if error.contains("could not atomically install") {
            "the private credential file could not be installed".to_owned()
        } else {
            "the private credential file could not be written".to_owned()
        }
    })
}

/// Unpredictable bytes from the operating system entropy source; login
/// never derives secrets from time, identity, or repository content.
fn os_random<const N: usize>() -> Result<[u8; N], String> {
    let bytes = os_random_bytes(N)?;
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The PKCE pair for one login: a high-entropy verifier plus its S256
/// challenge, per RFC 7636.
fn pkce_pair(random: &[u8; 32]) -> (String, String) {
    let verifier = BASE64URL_NOPAD.encode(random);
    let challenge = BASE64URL_NOPAD.encode(Sha256::digest(verifier.as_bytes()).as_slice());
    (verifier, challenge)
}

static OAUTH_HTTP: LazyLock<Result<reqwest::Client, String>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "the OAuth HTTP client could not be initialized".to_owned())
});

/// The HTTP client for every OAuth call: redirects are disabled so a
/// token endpoint can never bounce credentials elsewhere. Built once;
/// connect and request deadlines stay on this client because every
/// caller wants the same pair.
fn oauth_http_client() -> Result<&'static reqwest::Client, String> {
    OAUTH_HTTP.as_ref().map_err(Clone::clone)
}

/// One bounded form POST. Never returns upstream bodies in errors: the
/// parsed JSON document is the only content that escapes, and callers
/// reduce it to static facts.
async fn post_form(
    client: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> Result<(u16, Value), String> {
    let response = client
        .post(url)
        .form(form)
        .send()
        .await
        .map_err(|_| "the authorization endpoint could not be reached".to_owned())?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "the authorization response could not be read".to_owned())?
    {
        if body.len() as u64 + chunk.len() as u64 > OAUTH_RESPONSE_MAX_BYTES {
            return Err("the authorization response exceeded its byte bound".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    let document: Value = serde_json::from_slice(&body)
        .map_err(|_| "the authorization response was not a JSON document".to_owned())?;
    Ok((status, document))
}

/// Reads a bounded UTF-8 document; oversize input is refused before any
/// parsing.
fn read_bounded_document(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| "the client configuration file could not be opened".to_owned())?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "the client configuration file could not be read".to_owned())?;
    if bytes.len() as u64 > max_bytes {
        return Err("the client configuration document exceeds its size bound".to_owned());
    }
    String::from_utf8(bytes)
        .map_err(|_| "the client configuration document is not UTF-8".to_owned())
}

/// A bounded secret token value: present, in bounds, no whitespace or
/// control characters.
fn token_value(document: &Value, key: &str, max_chars: usize) -> Option<String> {
    document
        .get(key)?
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.chars().count() <= max_chars
                && value.chars().all(|c| !c.is_control() && !c.is_whitespace())
        })
        .map(str::to_owned)
}

/// Reads a private mode-0600 UTF-8 secret file under a hard byte bound.
fn read_private_document(path: &Path, max_bytes: u64) -> Result<String, String> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::metadata(path)
        .map_err(|_| "the private credential file could not be inspected".to_owned())?;
    if !metadata.is_file() {
        return Err("the private credential path must name a regular file".to_owned());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err("the private credential file must have mode 0600".to_owned());
    }
    if metadata.len() > max_bytes {
        return Err("the private credential file exceeds its size bound".to_owned());
    }
    let mut file = std::fs::File::open(path)
        .map_err(|_| "the private credential file could not be opened".to_owned())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "the private credential file could not be read".to_owned())?;
    if bytes.len() as u64 > max_bytes {
        return Err("the private credential file exceeds its size bound".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "the private credential file is not UTF-8".to_owned())
}

/// Extends one existing provider bundle with a separately issued CalDAV
/// Basic pair. The app token is read from a private file, never argv, and
/// the target is atomically replaced at mode 0600.
fn configure_caldav(
    arguments: CaldavConfigureArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    let account = validate_account(&arguments.account)?;
    validate_token_path(&arguments.token_path)?;
    validate_token_path(&arguments.app_token_path)?;
    if arguments.user.is_empty()
        || arguments.user.chars().count() > MAX_ACCOUNT_CHARS
        || arguments.user != arguments.user.trim()
        || arguments.user.chars().any(char::is_control)
        || arguments.user.contains(':')
        || arguments.user.contains('$')
    {
        return Err(
            "the CalDAV user must be 1 to 128 non-control characters without ':', '$', or surrounding whitespace"
                .to_owned(),
        );
    }
    let raw = read_private_document(&arguments.token_path, MICROSOFT_CREDENTIAL_MAX_BYTES as u64)?;
    let mut document: Value = serde_json::from_str(&raw)
        .map_err(|_| "the provider credential bundle is not a JSON document".to_owned())?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| "the provider credential bundle is not a JSON object".to_owned())?;
    if object.get("version").and_then(Value::as_u64)
        != Some(u64::from(MICROSOFT_MAIL_CREDENTIAL_VERSION))
        || object.get("account").and_then(Value::as_str) != Some(account)
    {
        return Err(
            "the provider credential bundle does not bind this account and schema".to_owned(),
        );
    }
    let app_token = read_private_document(&arguments.app_token_path, 1_024)?;
    let app_token = app_token.trim_end_matches(['\r', '\n']);
    if app_token.is_empty()
        || app_token.chars().count() > 512
        || app_token
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("the CalDAV app token is empty or outside its character bound".to_owned());
    }
    object.insert(
        "caldav_basic".to_owned(),
        serde_json::json!({
            "user": arguments.user,
            "password": app_token,
        }),
    );
    let mut rendered = serde_json::to_vec_pretty(&document)
        .map_err(|_| "the provider credential bundle could not be rendered".to_owned())?;
    rendered.push(b'\n');
    if rendered.len() > MICROSOFT_CREDENTIAL_MAX_BYTES {
        return Err("the provider credential bundle exceeds its size bound".to_owned());
    }
    write_private_atomic(&arguments.token_path, &rendered)?;
    report(
        output,
        &format!(
            "CalDAV credentials installed into {} (mode 0600)",
            arguments.token_path.display()
        ),
    )?;
    Ok(RunStatus::Success)
}

/// A bounded device-flow document field: present, in bounds, no control
/// characters.
fn device_field(document: &Value, key: &str, max_chars: usize) -> Option<String> {
    document
        .get(key)?
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.chars().count() <= max_chars
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

/// The access lifetime in seconds, bounded to one day.
fn token_lifetime(document: &Value) -> Option<i64> {
    document
        .get("expires_in")?
        .as_i64()
        .filter(|seconds| (1..=86_400).contains(seconds))
}

/// One completed grant: the facts every install needs and the only ones
/// kept.
struct TokenGrant {
    access: String,
    refresh: String,
    expires_in: i64,
}

// ---------------------------------------------------------------------------
// Google loopback login
// ---------------------------------------------------------------------------

fn login_google(arguments: GoogleLoginArgs, output: &mut impl Write) -> Result<RunStatus, String> {
    let account = validate_account(&arguments.account)?;
    validate_token_path(&arguments.token_path)?;
    // All input parsing happens before any network call: the downloaded
    // client document is bounded, parsed, and its secret kept only in
    // memory for this login.
    let raw_document =
        read_bounded_document(&arguments.client_config, GOOGLE_CLIENT_DOCUMENT_MAX_BYTES)?;
    let client = GoogleInstalledClient::from_installed_json(&raw_document).map_err(|_| {
        "the client configuration is not a Google Desktop client document carrying client_id and client_secret"
            .to_owned()
    })?;
    ensure_private_parent(&arguments.token_path)?;
    let scopes = if arguments.calendar_only {
        GOOGLE_CALENDAR_ONLY_SCOPES
    } else {
        GOOGLE_SCOPES
    };

    let runtime = login_runtime()?;
    runtime.block_on(google_consent_flow(
        account,
        &client,
        &arguments.token_path,
        scopes,
        output,
    ))?;
    Ok(RunStatus::Success)
}

async fn google_consent_flow(
    account: &str,
    client: &GoogleInstalledClient,
    token_path: &Path,
    scopes: &[&str],
    output: &mut impl Write,
) -> Result<(), String> {
    let http = oauth_http_client()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "could not bind the loopback consent listener".to_owned())?;
    let port = listener
        .local_addr()
        .map_err(|_| "could not inspect the loopback consent listener".to_owned())?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}");
    let (verifier, code_challenge) = pkce_pair(&os_random::<32>()?);
    let state = hex_string(&os_random::<16>()?);
    let consent_url = authorization_url(
        GOOGLE_AUTHORIZATION_URL,
        &client.client_id,
        &redirect_uri,
        scopes,
        &state,
        &code_challenge,
    )?;
    report(
        output,
        &format!("google sign-in for account {account}: open this consent URL in a browser and approve access:"),
    )?;
    report(output, &consent_url)?;
    report(
        output,
        &format!("waiting for the loopback callback on 127.0.0.1:{port} ..."),
    )?;
    let code = await_loopback_code(&listener, &state).await?;
    let form = [
        ("code", code.as_str()),
        ("client_id", client.client_id.as_str()),
        ("client_secret", client.client_secret.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
        ("code_verifier", verifier.as_str()),
    ];
    let (status, document) = post_form(http, GOOGLE_TOKEN_URL, &form).await?;
    let grant = parse_google_grant(status, &document)?;
    let token_file = client
        .token_file(
            &grant.refresh,
            &grant.access,
            OffsetDateTime::now_utc() + time::Duration::seconds(grant.expires_in),
        )
        .map_err(|fault| format!("the Google token record was refused before install: {fault}"))?;
    token_file.write_private(token_path).map_err(|fault| {
        format!("the Google token file could not be installed privately: {fault}")
    })?;
    report(
        output,
        &format!(
            "google login complete: token file installed at {} (mode 0600)",
            token_path.display()
        ),
    )
}

/// The exact consent URL for one login: response-type code, PKCE S256,
/// offline access, and the five provider scopes.
fn authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[&str],
    state: &str,
    code_challenge: &str,
) -> Result<String, String> {
    let mut url = Url::parse(endpoint)
        .map_err(|_| "the configured authorization endpoint is not a URL".to_owned())?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent");
    Ok(url.to_string())
}

/// Accepts the one bounded loopback callback: verifies the state on
/// every request, answers each request once, and returns the code only
/// from the request that matches this login.
async fn await_loopback_code(
    listener: &tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(LOOPBACK_BUDGET_SECONDS);
    for _ in 0..LOOPBACK_MAX_CALLBACKS {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let accepted = tokio::time::timeout(remaining, listener.accept()).await;
        let Ok(accepted) = accepted else { break };
        let (mut stream, _) =
            accepted.map_err(|_| "the loopback consent listener failed".to_owned())?;
        match answer_callback(&mut stream, expected_state).await {
            Some(outcome) => return outcome,
            None => continue,
        }
    }
    Err("no valid consent callback arrived before the loopback budget was exhausted; run the login again".to_owned())
}

enum ParsedCallback {
    Code(String),
    Denied,
    ProviderError,
}

async fn answer_callback(
    stream: &mut tokio::net::TcpStream,
    expected_state: &str,
) -> Option<Result<String, String>> {
    let head = match tokio::time::timeout(LOOPBACK_IO_TIMEOUT, read_request_head(stream)).await {
        Ok(Ok(head)) => head,
        Ok(Err(())) | Err(_) => return None,
    };
    let Some(parsed) = parse_callback_request(&head, expected_state) else {
        respond(stream, 400, CALLBACK_REFUSED_BODY).await;
        return None;
    };
    match parsed {
        ParsedCallback::Code(code) => {
            respond(stream, 200, CALLBACK_ACCEPTED_BODY).await;
            Some(Ok(code))
        }
        ParsedCallback::Denied => {
            respond(stream, 200, CALLBACK_DENIED_BODY).await;
            Some(Err(
                "consent was refused in the browser; no grant was issued".to_owned(),
            ))
        }
        ParsedCallback::ProviderError => {
            respond(stream, 400, CALLBACK_REFUSED_BODY).await;
            Some(Err(
                "the provider returned an authorization error; no grant was issued".to_owned(),
            ))
        }
    }
}

async fn read_request_head(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>, ()> {
    use tokio::io::AsyncReadExt as _;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        head.extend_from_slice(&chunk[..read]);
        let complete = head.windows(4).any(|window| window == b"\r\n\r\n");
        if complete || head.len() > LOOPBACK_HEAD_MAX_BYTES {
            return Ok(head);
        }
    }
}

async fn respond(stream: &mut tokio::net::TcpStream, status: u16, body: &str) {
    use tokio::io::AsyncWriteExt as _;
    let reason = match status {
        200 => "OK",
        _ => "Bad Request",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Reduces one callback request head to a typed outcome. Anything that
/// is not a GET of this login's exact state — including a provider
/// error or a state mismatch — is refused; no value escapes unverified.
fn parse_callback_request(head: &[u8], expected_state: &str) -> Option<ParsedCallback> {
    let head = std::str::from_utf8(head).ok()?;
    let request_line = head.lines().next()?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let query = match target.split_once('?') {
        Some(("/", query)) => query,
        _ => return None,
    };
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut denied = false;
    let mut provider_error = false;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" if value == "access_denied" => denied = true,
            "error" => provider_error = true,
            _ => {}
        }
    }
    if denied {
        return Some(ParsedCallback::Denied);
    }
    if provider_error {
        return Some(ParsedCallback::ProviderError);
    }
    let code = code.filter(|value| {
        !value.is_empty()
            && value.chars().count() <= AUTH_CODE_MAX_CHARS
            && !value.chars().any(char::is_control)
    })?;
    if state.as_deref() != Some(expected_state) {
        return None;
    }
    Some(ParsedCallback::Code(code))
}

/// Reduces the code-exchange response to typed facts. Non-200 answers
/// and every body value stay here: errors are static and sanitized.
fn parse_google_grant(status: u16, document: &Value) -> Result<TokenGrant, String> {
    if status != 200 {
        return Err(
            "the Google token endpoint rejected the authorization code; run the login again"
                .to_owned(),
        );
    }
    let Some(access) = token_value(document, "access_token", GOOGLE_TOKEN_VALUE_CHARS) else {
        return Err("the Google token response did not carry a usable access token".to_owned());
    };
    let Some(refresh) = token_value(document, "refresh_token", GOOGLE_TOKEN_VALUE_CHARS) else {
        return Err("Google did not grant a refresh token; revoke this application's access in the Google account settings and run the login again so offline consent can be captured".to_owned());
    };
    let Some(expires_in) = token_lifetime(document) else {
        return Err("the Google token response lifetime is missing or out of bounds".to_owned());
    };
    Ok(TokenGrant {
        access,
        refresh,
        expires_in,
    })
}

// ---------------------------------------------------------------------------
// Microsoft mail device login
// ---------------------------------------------------------------------------

/// Preserves the independently issued CalDAV app token across a later
/// Microsoft mail re-consent. A missing bundle is the first-login case;
/// an existing malformed or foreign bundle is refused before OAuth starts.
fn existing_caldav_basic(path: &Path, account: &str) -> Result<Option<Value>, String> {
    if !path
        .try_exists()
        .map_err(|_| "the private credential path could not be inspected".to_owned())?
    {
        return Ok(None);
    }
    let raw = read_private_document(path, MICROSOFT_CREDENTIAL_MAX_BYTES as u64)?;
    let document: Value = serde_json::from_str(&raw)
        .map_err(|_| "the provider credential bundle is not a JSON document".to_owned())?;
    if document.get("version").and_then(Value::as_u64)
        != Some(u64::from(MICROSOFT_MAIL_CREDENTIAL_VERSION))
        || document.get("account").and_then(Value::as_str) != Some(account)
    {
        return Err(
            "the provider credential bundle does not bind this account and schema".to_owned(),
        );
    }
    let Some(basic) = document.get("caldav_basic") else {
        return Ok(None);
    };
    let user = basic
        .get("user")
        .and_then(Value::as_str)
        .filter(|user| {
            !user.is_empty()
                && user.chars().count() <= MAX_ACCOUNT_CHARS
                && !user.chars().any(char::is_control)
        })
        .ok_or_else(|| "the existing CalDAV credential is outside its bounds".to_owned())?;
    let password = basic
        .get("password")
        .and_then(Value::as_str)
        .filter(|password| {
            !password.is_empty()
                && password.chars().count() <= 512
                && !password
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
        })
        .ok_or_else(|| "the existing CalDAV credential is outside its bounds".to_owned())?;
    Ok(Some(serde_json::json!({
        "user": user,
        "password": password,
    })))
}

fn login_microsoft_mail(
    arguments: MicrosoftMailLoginArgs,
    output: &mut impl Write,
) -> Result<RunStatus, String> {
    let account = validate_account(&arguments.account)?;
    validate_token_path(&arguments.token_path)?;
    let tenant = validate_tenant(&arguments.tenant)?;
    ensure_private_parent(&arguments.token_path)?;
    let device_url = microsoft_endpoint(tenant, "devicecode");
    let token_url = microsoft_endpoint(tenant, "token");
    let runtime = login_runtime()?;
    runtime.block_on(microsoft_consent_flow(
        account,
        tenant,
        &device_url,
        &token_url,
        &arguments.token_path,
        arguments.probe_graph_calendar,
        output,
    ))?;
    Ok(RunStatus::Success)
}

/// The v2 device-code and token endpoints for one validated tenant; the
/// tenant charset is proven by [`validate_tenant`] before this format.
fn microsoft_endpoint(tenant: &str, action: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{action}")
}

async fn microsoft_consent_flow(
    account: &str,
    tenant: &str,
    device_url: &str,
    token_url: &str,
    token_path: &Path,
    probe_graph_calendar: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let caldav_basic = existing_caldav_basic(token_path, account)?;
    let http = oauth_http_client()?;
    let challenge = start_device_flow(http, device_url, MICROSOFT_MAIL_SCOPE).await?;
    report(
        output,
        &format!(
            "microsoft-mail sign-in for account {account}: open {} and enter the code {}",
            challenge.verification_uri, challenge.user_code
        ),
    )?;
    report(
        output,
        &format!(
            "waiting for consent (the sign-in code expires in about {} minutes) ...",
            (challenge.expires_in / 60).max(1)
        ),
    )?;
    let grant = poll_device_token(http, token_url, &challenge)
        .await
        .map_err(|failure| failure.message().to_owned())?;
    let bundle = microsoft_bundle_json(
        account,
        tenant,
        &grant,
        OffsetDateTime::now_utc() + time::Duration::seconds(grant.expires_in),
        caldav_basic.as_ref(),
    )?;
    write_private_atomic(token_path, &bundle)?;
    report(
        output,
        &format!(
            "microsoft-mail login complete: credential bundle installed at {} (mode 0600)",
            token_path.display()
        ),
    )?;
    if probe_graph_calendar {
        run_graph_probe(http, device_url, token_url, output).await;
    }
    Ok(())
}

/// One device-code challenge. `device_code` is a secret: it is only
/// ever sent back to the token endpoint, never printed or stored.
struct DeviceChallenge {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval_seconds: u64,
}

async fn start_device_flow(
    http: &reqwest::Client,
    device_url: &str,
    scope: &str,
) -> Result<DeviceChallenge, String> {
    let form = [
        ("client_id", MICROSOFT_THUNDERBIRD_CLIENT_ID),
        ("scope", scope),
    ];
    let (status, document) = post_form(http, device_url, &form).await?;
    if status != 200 {
        return Err("the Microsoft device-code endpoint rejected the sign-in request".to_owned());
    }
    parse_device_challenge(&document)
}

fn parse_device_challenge(document: &Value) -> Result<DeviceChallenge, String> {
    const MSG_SHAPE: &str = "the Microsoft device-code response was not the expected shape";
    // Current Entra device codes exceed 1 KiB; keep a bounded 2 KiB envelope.
    let device_code =
        device_field(document, "device_code", 2_048).ok_or_else(|| MSG_SHAPE.to_owned())?;
    let user_code = document
        .get("user_code")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.chars().count() <= 32
                && value.chars().all(|char| char.is_ascii_graphic())
        })
        .ok_or_else(|| MSG_SHAPE.to_owned())?
        .to_owned();
    let verification_uri = document
        .get("verification_uri")
        .and_then(Value::as_str)
        .filter(|value| {
            value.starts_with("https://")
                && value.len() <= 2048
                && value.chars().all(|c| !c.is_control() && !c.is_whitespace())
        })
        .ok_or_else(|| MSG_SHAPE.to_owned())?
        .to_owned();
    let expires_in = token_lifetime(document)
        .filter(|seconds| *seconds >= 60)
        .ok_or_else(|| {
            "the Microsoft device-code response lifetime is missing or out of bounds".to_owned()
        })?;
    let interval_seconds = document
        .get("interval")
        .and_then(Value::as_u64)
        .filter(|seconds| (1..=MICROSOFT_MAX_POLL_SECONDS).contains(seconds))
        .unwrap_or(MICROSOFT_DEFAULT_POLL_SECONDS);
    Ok(DeviceChallenge {
        device_code,
        user_code,
        verification_uri,
        expires_in,
        interval_seconds,
    })
}

enum PollFailure {
    Denied,
    Expired,
    Rejected,
    MissingRefresh,
}

impl PollFailure {
    fn message(&self) -> &'static str {
        match self {
            Self::Denied => {
                "consent was refused on the verification page; no credential was issued"
            }
            Self::Expired => {
                "the device code expired before consent completed; run the login again"
            }
            Self::Rejected => "the Microsoft token endpoint rejected the device sign-in",
            Self::MissingRefresh => {
                "Microsoft did not return a refresh token; the sign-in consent was incomplete"
            }
        }
    }
}

enum PollStep {
    Complete {
        access: String,
        refresh: Option<String>,
        expires_in: i64,
    },
    Pending,
    SlowDown,
    Denied,
    Expired,
    Rejected,
}

/// Reduces one poll response to a typed protocol step. Body values never
/// leave this function except the typed token facts of a complete step.
fn classify_microsoft_poll(status: u16, document: &Value) -> PollStep {
    if status == 200 {
        let Some(access) = token_value(document, "access_token", MICROSOFT_TOKEN_VALUE_CHARS)
        else {
            return PollStep::Rejected;
        };
        let refresh = token_value(document, "refresh_token", MICROSOFT_TOKEN_VALUE_CHARS);
        let Some(expires_in) = token_lifetime(document) else {
            return PollStep::Rejected;
        };
        return PollStep::Complete {
            access,
            refresh,
            expires_in,
        };
    }
    match document.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => PollStep::Pending,
        Some("slow_down") => PollStep::SlowDown,
        Some("access_denied") => PollStep::Denied,
        Some("expired_token") | Some("authorization_expired") => PollStep::Expired,
        _ => PollStep::Rejected,
    }
}

/// Polls per the device-code protocol: sleep the advertised interval,
/// honor `slow_down` (+5s), stop at the advertised expiry under a hard
/// budget, and require the refresh grant before returning. No other
/// retry exists.
async fn poll_device_token(
    http: &reqwest::Client,
    token_url: &str,
    challenge: &DeviceChallenge,
) -> Result<TokenGrant, PollFailure> {
    let budget = challenge
        .expires_in
        .clamp(60, MICROSOFT_POLL_HARD_BUDGET_SECONDS) as u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(budget);
    let mut interval = challenge.interval_seconds;
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if std::time::Instant::now() >= deadline {
            return Err(PollFailure::Expired);
        }
        let form = [
            ("grant_type", MICROSOFT_DEVICE_GRANT),
            ("client_id", MICROSOFT_THUNDERBIRD_CLIENT_ID),
            ("device_code", challenge.device_code.as_str()),
        ];
        let Ok((status, document)) = post_form(http, token_url, &form).await else {
            return Err(PollFailure::Rejected);
        };
        match classify_microsoft_poll(status, &document) {
            PollStep::Pending => continue,
            PollStep::SlowDown => {
                interval = (interval + 5).min(MICROSOFT_MAX_POLL_SECONDS);
                continue;
            }
            PollStep::Complete {
                access,
                refresh,
                expires_in,
            } => {
                let Some(refresh) = refresh else {
                    return Err(PollFailure::MissingRefresh);
                };
                return Ok(TokenGrant {
                    access,
                    refresh,
                    expires_in,
                });
            }
            PollStep::Denied => return Err(PollFailure::Denied),
            PollStep::Expired => return Err(PollFailure::Expired),
            PollStep::Rejected => return Err(PollFailure::Rejected),
        }
    }
}

/// The exact credential bundle the generic IMAP/SMTP provider loads.
/// Refresh facts let the provider renew mail access before dispatch;
/// bounded token values keep the file inside the provider's 16 KiB cap.
/// A separately issued CalDAV app token is added only by
/// `odin account configure-caldav`; later mail re-consent preserves it.
fn microsoft_bundle_json(
    account: &str,
    tenant: &str,
    grant: &TokenGrant,
    expires_at: OffsetDateTime,
    caldav_basic: Option<&Value>,
) -> Result<Vec<u8>, String> {
    let expires_at = expires_at
        .format(&Rfc3339)
        .map_err(|_| "the credential expiry could not be rendered".to_owned())?;
    let mut document = serde_json::json!({
        "version": MICROSOFT_MAIL_CREDENTIAL_VERSION,
        "account": account,
        "user": account,
        "access_token": grant.access.as_str(),
        "refresh_token": grant.refresh.as_str(),
        "client_id": MICROSOFT_THUNDERBIRD_CLIENT_ID,
        "tenant": tenant,
        "expires_at": expires_at,
    });
    if let Some(caldav_basic) = caldav_basic {
        document
            .as_object_mut()
            .expect("the static credential document is an object")
            .insert("caldav_basic".to_owned(), caldav_basic.clone());
    }
    let bytes = serde_json::to_vec_pretty(&document)
        .map_err(|_| "the credential bundle could not be rendered".to_owned())?;
    if bytes.len() > MICROSOFT_CREDENTIAL_MAX_BYTES {
        return Err("the credential bundle exceeds the generic provider's size bound".to_owned());
    }
    Ok(bytes)
}

/// The explicit direct-Graph consent probe: one Calendars.ReadWrite
/// device flow, reported only. Nothing is configured, stored, or
/// shipped for Graph, and the probe can never fail the completed mail
/// login.
async fn run_graph_probe(
    http: &reqwest::Client,
    device_url: &str,
    token_url: &str,
    output: &mut impl Write,
) {
    let Ok(challenge) = start_device_flow(http, device_url, MICROSOFT_GRAPH_PROBE_SCOPE).await
    else {
        let _ = report(
            output,
            "graph calendar probe failed: the device-code request was rejected",
        );
        return;
    };
    let _ = report(
        output,
        &format!(
            "graph calendar probe: open {} and enter the code {} (consent covers only Calendars.ReadWrite)",
            challenge.verification_uri, challenge.user_code
        ),
    );
    match poll_device_token(http, token_url, &challenge).await {
        Ok(_) => {
            let _ = report(
                output,
                "graph calendar probe: consent granted; no Graph backend was configured and no credential was stored",
            );
        }
        Err(PollFailure::Denied) => {
            let _ = report(
                output,
                "graph calendar probe: consent refused; no Graph backend was configured",
            );
        }
        Err(_) => {
            let _ = report(
                output,
                "graph calendar probe: failed before a consent grant; no Graph backend was configured",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        authorization_url, configure_caldav, existing_caldav_basic, microsoft_bundle_json,
        parse_device_challenge, CaldavConfigureArgs, TokenGrant, GOOGLE_AUTHORIZATION_URL,
        GOOGLE_CALENDAR_ONLY_SCOPES, GOOGLE_SCOPE_CALENDAR_EVENTS,
    };

    #[test]
    fn accepts_current_entra_device_code_length() {
        let document = serde_json::json!({
            "device_code": "x".repeat(1_045),
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 900,
            "interval": 5,
        });

        let challenge = parse_device_challenge(&document).expect("current Entra response");
        assert_eq!(challenge.device_code.len(), 1_045);
    }

    #[test]
    fn calendar_only_consent_requests_no_gmail_scope() {
        let rendered = authorization_url(
            GOOGLE_AUTHORIZATION_URL,
            "client",
            "http://127.0.0.1:12345",
            GOOGLE_CALENDAR_ONLY_SCOPES,
            "state",
            "challenge",
        )
        .expect("the consent URL renders");
        let parsed = url::Url::parse(&rendered).expect("the consent URL parses");
        let scope = parsed
            .query_pairs()
            .find_map(|(name, value)| (name == "scope").then(|| value.into_owned()))
            .expect("scope is present");
        assert_eq!(scope, GOOGLE_SCOPE_CALENDAR_EVENTS);
        assert!(!scope.contains("gmail"));
    }

    #[test]
    fn configures_private_caldav_basic_without_exposing_the_token() {
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let target = directory.path().join("microsoft.json");
        std::fs::write(
            &target,
            br#"{"version":1,"account":"colin@example.com","user":"colin@example.com"}"#,
        )
        .expect("target writes");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("target is private");
        let app_token = directory.path().join("app-token");
        std::fs::write(&app_token, b"abcd_0123456789\n").expect("app token writes");
        std::fs::set_permissions(&app_token, std::fs::Permissions::from_mode(0o600))
            .expect("app token is private");
        let mut output = Vec::new();

        configure_caldav(
            CaldavConfigureArgs {
                account: "colin@example.com".to_owned(),
                token_path: target.clone(),
                user: "colin".to_owned(),
                app_token_path: app_token,
            },
            &mut output,
        )
        .expect("CalDAV binding succeeds");

        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).expect("target reads"))
                .expect("target remains JSON");
        assert_eq!(document["caldav_basic"]["user"], "colin");
        assert_eq!(document["caldav_basic"]["password"], "abcd_0123456789");
        assert!(!String::from_utf8(output)
            .unwrap()
            .contains("abcd_0123456789"));
        assert_eq!(
            std::fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let preserved = existing_caldav_basic(&target, "colin@example.com")
            .expect("existing credential is valid");
        let refreshed = microsoft_bundle_json(
            "colin@example.com",
            "caltech.edu",
            &TokenGrant {
                access: "new-mail-access".to_owned(),
                refresh: "new-mail-refresh".to_owned(),
                expires_in: 3600,
            },
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            preserved.as_ref(),
        )
        .expect("mail re-consent bundle renders");
        let refreshed: serde_json::Value =
            serde_json::from_slice(&refreshed).expect("refreshed bundle is JSON");
        assert_eq!(refreshed["access_token"], "new-mail-access");
        assert_eq!(refreshed["caldav_basic"], document["caldav_basic"]);
    }
}
