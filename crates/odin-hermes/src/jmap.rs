//! JMAP email and calendar exchanges over configured HTTPS endpoints.
//!
//! Requests POST method calls to the session API URL; credentials are read per exchange and sent as bearer headers.
//! Responses are byte-limited, and faults exclude upstream bodies, URLs, and credential values.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use odin_domain::huginn::OpaqueCredentialHandle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::account::{AccountSecretRef, ScopedCredentialLease, TransportFault};

/// Hard response-byte ceiling for one JMAP exchange when the
/// deployment config does not tighten it further.
pub const MAX_RESPONSE_BYTES: u64 = 8_388_608;

/// Per-exchange wall-clock ceiling when the deployment config does not
/// tighten it further.
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;

/// The `urn:ietf:params:jmap:core` capability urn.
pub const JMAP_CORE: &str = "urn:ietf:params:jmap:core";
/// The `urn:ietf:params:jmap:mail` capability urn.
pub const JMAP_MAIL: &str = "urn:ietf:params:jmap:mail";
/// The `urn:ietf:params:jmap:submission` capability urn.
pub const JMAP_SUBMISSION: &str = "urn:ietf:params:jmap:submission";
/// The `urn:ietf:params:jmap:calendars` capability urn.
pub const JMAP_CALENDARS: &str = "urn:ietf:params:jmap:calendars";

const MSG_SESSION_URL: &str = "the configured JMAP session URL is not HTTPS";
const MSG_SESSION_SHAPE: &str = "the JMAP session document was not the expected shape";
const MSG_CREDENTIAL_SHAPE: &str = "the resolved JMAP credential is not a usable token";
const MSG_CLIENT: &str = "the JMAP client could not be initialized";
const MSG_REDIRECTS: &str = "the JMAP session discovery exceeded its redirect bound";
const MSG_CONFIG: &str = "the JMAP endpoint configuration is incomplete";
const MSG_REJECTED: &str = "the JMAP service rejected the request";
const MSG_BODY: &str = "the JMAP response failed its byte bound";
const MSG_BODY_READ: &str = "the JMAP response body could not be read";
const MSG_PARSE: &str = "the JMAP response was not the expected shape";
const MSG_METHOD_ERROR: &str = "the JMAP service reported a method error";

/// One JMAP method invocation: the method name, its arguments, and the
/// caller-chosen invocation id the response references. On the wire it
/// is the RFC 8620 invocation triple `[["Name", {…}, "id"], …]` —
/// serialization emits exactly that array form; responses parse
/// through the separate [`JmapResponseCall`] shape.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct JmapCall {
    pub name: String,
    pub arguments: Value,
    pub call_id: String,
}

impl Serialize for JmapCall {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.name.as_str(), &self.arguments, self.call_id.as_str()).serialize(serializer)
    }
}

impl JmapCall {
    pub fn new(name: impl Into<String>, arguments: Value, call_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments,
            call_id: call_id.into(),
        }
    }
}

/// One JMAP request document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JmapRequest {
    pub using: Vec<String>,
    pub method_calls: Vec<JmapCall>,
}

/// One JMAP method response entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JmapResponseCall {
    pub name: String,
    pub arguments: Value,
    pub call_id: String,
}

/// One parsed JMAP response document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JmapResponse {
    pub responses: Vec<JmapResponseCall>,
}

impl JmapResponse {
    /// The response for one invocation id.
    pub fn find(&self, call_id: &str) -> Option<&JmapResponseCall> {
        self.responses.iter().find(|call| call.call_id == call_id)
    }

    /// Parses a raw response document: `{"methodResponses":
    /// [["Name", {…}, "id"], …]}`. Anything else is a typed protocol
    /// fault — never a fabricated success.
    pub fn parse(document: &Value) -> Result<Self, TransportFault> {
        let raw = document
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or(fault_parse())?;
        let mut responses = Vec::with_capacity(raw.len());
        for entry in raw {
            let parts = entry.as_array().ok_or(fault_parse())?;
            let [name, arguments, call_id] = parts.as_slice() else {
                return Err(fault_parse());
            };
            let name = name.as_str().ok_or(fault_parse())?;
            let call_id = call_id.as_str().ok_or(fault_parse())?;
            if !arguments.is_object() {
                return Err(fault_parse());
            }
            responses.push(JmapResponseCall {
                name: name.to_owned(),
                arguments: arguments.clone(),
                call_id: call_id.to_owned(),
            });
        }
        Ok(Self { responses })
    }
}

const fn fault_parse() -> TransportFault {
    TransportFault::Protocol(MSG_PARSE)
}

/// Maps one RFC 8620 §3.6.2 method-level `error` response onto the
/// typed fault surface. `accountNotFound` is a typed account
/// unavailability — checked before any shape parsing so a wrong or
/// unknown account never degrades into a shape fault. Every other
/// method error is a sanitized protocol fault.
pub(crate) fn method_fault(arguments: &Value) -> TransportFault {
    if arguments.get("type").and_then(Value::as_str) == Some("accountNotFound") {
        return TransportFault::Unavailable(crate::account::AccountUnavailable::Account);
    }
    TransportFault::Protocol(MSG_METHOD_ERROR)
}

/// Reports service unavailability only before dispatch; timeouts and protocol errors may have effects.
pub trait JmapExchange: Send + Sync {
    /// Local-only: whether this exchange could use its credential material
    /// right now. It must never contact the service.
    fn readiness(&self) -> Result<(), TransportFault>;

    fn exchange(
        &self,
        request: &JmapRequest,
        lease: &ScopedCredentialLease,
    ) -> Result<JmapResponse, TransportFault>;
}

/// Deployment facts for one JMAP account, all rendered from
/// Nix/dotfiles configuration. No field has a default.
#[derive(Clone, Debug)]
pub struct JmapEndpointConfig {
    /// The JMAP account id this deployment addresses; the session
    /// document must list it, else the account is typed unavailable.
    pub account_id: String,
    /// The account's JMAP session document URL (`/.well-known/jmap`);
    /// must be HTTPS.
    pub session_url: String,
    /// The credential reference: opaque handle + sops-rendered secret
    /// file the trusted backend resolves per exchange.
    pub credential: AccountSecretRef,
    /// Per-exchange deadline in milliseconds.
    pub request_timeout_ms: u64,
    /// Hard response-byte ceiling.
    pub max_response_bytes: u64,
}

impl JmapEndpointConfig {
    /// Validates and bounds the configured facts.
    pub fn validated(self) -> Result<Self, TransportFault> {
        if !self.session_url.starts_with("https://") {
            return Err(TransportFault::Protocol(MSG_SESSION_URL));
        }
        if self.account_id.trim().is_empty() {
            return Err(TransportFault::Protocol(MSG_CONFIG));
        }
        let timeout = self.request_timeout_ms.clamp(1, MAX_REQUEST_TIMEOUT_MS);
        let bytes = self.max_response_bytes.clamp(1_024, MAX_RESPONSE_BYTES);
        Ok(Self {
            account_id: self.account_id,
            session_url: self.session_url,
            credential: self.credential,
            request_timeout_ms: timeout,
            max_response_bytes: bytes,
        })
    }
}

/// The production HTTPS exchange: `reqwest::blocking`, one session GET
/// plus one API POST per exchange, bearer credential from the secret
/// file. Built for the one-shot supervised adapter process — never call
/// it from inside a Tokio runtime without `spawn_blocking`.
pub struct HttpsJmapExchange {
    config: JmapEndpointConfig,
}

impl HttpsJmapExchange {
    pub fn new(config: JmapEndpointConfig) -> Result<Self, TransportFault> {
        Ok(Self {
            config: config.validated()?,
        })
    }

    fn deadline(&self) -> Duration {
        Duration::from_millis(self.config.request_timeout_ms)
    }

    /// Resolves the sops-rendered bearer token through the separate
    /// resolution stage ([`resolve_bearer`]). The value stays inside
    /// the runtime-only [`BearerToken`] wrapper.
    fn bearer(&self) -> Result<BearerToken, TransportFault> {
        resolve_bearer(self.config.credential.secret_path())
    }
}

/// A resolved credential value, confined to the runtime. It implements
/// neither `Serialize` nor `Clone`-to-string: the value is readable
/// only inside this module (the authorization frame), its `Debug`
/// redacts, and no model-facing surface can extract it.
pub struct BearerToken(String);

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

impl BearerToken {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// Resolves secret material separately from lease issuance into a redacted backend-only wrapper.
pub fn resolve_bearer(secret_path: &std::path::Path) -> Result<BearerToken, TransportFault> {
    let secret = std::fs::read_to_string(secret_path).map_err(|_| {
        TransportFault::Unavailable(crate::account::AccountUnavailable::Credentials)
    })?;
    let token = secret.trim();
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(TransportFault::Protocol(MSG_CREDENTIAL_SHAPE));
    }
    Ok(BearerToken(token.to_owned()))
}

/// The session document fields this exchange consumes. `accounts` and
/// `capabilities` must be present for validation.
#[derive(Deserialize)]
struct JmapSession {
    #[serde(rename = "apiUrl")]
    api_url: String,
    #[serde(default)]
    accounts: serde_json::Map<String, Value>,
    #[serde(default)]
    capabilities: serde_json::Map<String, Value>,
}

/// Reads one response document under the hard byte ceiling using a
/// bounded reader: chunked or length-less bodies are cut off at
/// `max + 1` bytes instead of buffered whole before the check.
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
    serde_json::from_slice(&bytes).map_err(|_| TransportFault::Protocol(MSG_PARSE))
}

/// Bounded redirect discovery (RFC 8620 §2.2): session discovery may
/// redirect, but only within HTTPS and only a bounded number of hops.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 3 {
            attempt.error(MSG_REDIRECTS)
        } else if attempt.url().scheme() != "https" {
            attempt.error(MSG_SESSION_URL)
        } else {
            attempt.follow()
        }
    })
}
static CLIENT: LazyLock<Result<reqwest::blocking::Client, reqwest::Error>> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .redirect(redirect_policy())
        .build()
});

fn client() -> Result<&'static reqwest::blocking::Client, TransportFault> {
    CLIENT
        .as_ref()
        .map_err(|_| TransportFault::Protocol(MSG_CLIENT))
}

impl JmapExchange for HttpsJmapExchange {
    fn readiness(&self) -> Result<(), TransportFault> {
        self.bearer().map(|_| ())
    }

    fn exchange(
        &self,
        request: &JmapRequest,
        lease: &ScopedCredentialLease,
    ) -> Result<JmapResponse, TransportFault> {
        use crate::account::AccountUnavailable;

        // The lease must bind exactly this deployment's credential
        // reference; a lease minted for another deployment is a
        // protocol failure, never a best-effort dispatch.
        let handle: OpaqueCredentialHandle = self.config.credential.handle().clone();
        if !lease.binds_handle(&handle) {
            return Err(TransportFault::Refused(
                "the credential lease does not bind this deployment",
            ));
        }
        let token = self.bearer()?;
        let client = client()?;
        let deadline = self.deadline();
        let session_bytes = client
            .get(&self.config.session_url)
            .timeout(deadline)
            .bearer_auth(token.expose())
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(map_request_error)?;
        let document = read_bounded(session_bytes, self.config.max_response_bytes)?;
        let session: JmapSession = serde_json::from_value(document)
            .map_err(|_| TransportFault::Protocol(MSG_SESSION_SHAPE))?;
        if !session.api_url.starts_with("https://") {
            return Err(TransportFault::Protocol(MSG_SESSION_SHAPE));
        }
        // The configured account must exist in the session, and every
        // capability the request needs must be available to that
        // account: core is a server-level capability, while extension
        // capabilities must be advertised in the account's own
        // accountCapabilities map (RFC 8620 §2). Both are typed account
        // failures, checked before any method call so accountNotFound
        // never degrades into a shape fault.
        let account = session
            .accounts
            .get(&self.config.account_id)
            .ok_or(TransportFault::Unavailable(AccountUnavailable::Account))?;
        let account_capabilities = account
            .get("accountCapabilities")
            .and_then(Value::as_object);
        for urn in &request.using {
            if urn.as_str() == JMAP_CORE {
                if !session.capabilities.contains_key(urn) {
                    return Err(TransportFault::Unavailable(AccountUnavailable::Account));
                }
                continue;
            }
            let supported = account_capabilities
                .map(|capabilities| capabilities.contains_key(urn))
                // A session without the account's capability map proves
                // nothing beyond existence; fall back to the server's
                // own advertisement.
                .unwrap_or_else(|| session.capabilities.contains_key(urn));
            if !supported {
                return Err(TransportFault::Unavailable(AccountUnavailable::Account));
            }
        }

        post_api(
            client,
            &session.api_url,
            deadline,
            &token,
            request,
            self.config.max_response_bytes,
        )
    }
}

/// The method POST of one exchange: the request document leaves for the
/// discovered API URL and the bounded reply is parsed.
fn post_api(
    client: &reqwest::blocking::Client,
    api_url: &str,
    deadline: Duration,
    token: &BearerToken,
    request: &JmapRequest,
    max_response_bytes: u64,
) -> Result<JmapResponse, TransportFault> {
    let response = client
        .post(api_url)
        .timeout(deadline)
        .bearer_auth(token.expose())
        .json(request)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(map_method_error)?;
    let document = read_bounded(response, max_response_bytes)?;
    JmapResponse::parse(&document)
}

/// A method POST can have landed before a request-kind or unknown send
/// failure. Only connect/build failures prove it never dispatched.
fn map_method_error(error: reqwest::Error) -> TransportFault {
    let undispatched = error.is_connect() || error.is_builder();
    match map_request_error(error) {
        TransportFault::Unavailable(crate::account::AccountUnavailable::Service)
            if !undispatched =>
        {
            TransportFault::Protocol("the JMAP method reply was lost after possible dispatch")
        }
        fault => fault,
    }
}

/// Session-discovery faults precede every mutation. Keep their existing
/// typed deadline, credential, redirect and bounded-body diagnostics.
fn map_request_error(error: reqwest::Error) -> TransportFault {
    if error.is_timeout() {
        return TransportFault::Timeout;
    }
    // A refused redirect is a protocol failure: the server responded, so it is not unavailable.
    if error.is_redirect() {
        return match error.url() {
            Some(url) if url.scheme() != "https" => TransportFault::Protocol(MSG_SESSION_URL),
            _ => TransportFault::Protocol(MSG_REDIRECTS),
        };
    }
    if error.is_connect() || error.is_request() {
        return TransportFault::Unavailable(crate::account::AccountUnavailable::Service);
    }
    if let Some(status) = error.status() {
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return TransportFault::Unavailable(crate::account::AccountUnavailable::Credentials);
        }
        return TransportFault::ProtocolDetail {
            message: MSG_REJECTED,
            status: status.as_u16(),
        };
    }
    if error.is_body() || error.is_decode() {
        return TransportFault::Protocol(MSG_BODY_READ);
    }
    TransportFault::Unavailable(crate::account::AccountUnavailable::Service)
}

/// Convenience constructor shared by the email and calendar transports:
/// builds `Arc<dyn JmapExchange>` over the HTTPS implementation.
pub fn https_exchange(config: JmapEndpointConfig) -> Result<Arc<dyn JmapExchange>, TransportFault> {
    Ok(Arc::new(HttpsJmapExchange::new(config)?))
}

#[cfg(test)]
mod lost_reply_tests {
    use super::*;
    use crate::account::{
        CredentialLeases, EffectIdentity, FileCredentialLeases, HostConsumeProof, LifeError,
    };
    use crate::calendar::{
        CalendarAdapter, CalendarEventDraft, CalendarMutation, CalendarProposal,
        JmapCalendarConfig, JmapCalendarTransport,
    };
    use odin_ledger::Ledger;
    use std::io::{BufRead, BufReader, Read};

    /// The production client and method POST against a discovered API URL;
    /// only HTTPS session discovery is skipped (the URL is a loopback).
    struct DiscoveredApi {
        api_url: String,
    }

    impl JmapExchange for DiscoveredApi {
        fn readiness(&self) -> Result<(), TransportFault> {
            Ok(())
        }

        fn exchange(
            &self,
            request: &JmapRequest,
            _lease: &ScopedCredentialLease,
        ) -> Result<JmapResponse, TransportFault> {
            let token = BearerToken("fixture-bearer".to_owned());
            post_api(
                client()?,
                &self.api_url,
                Duration::from_secs(5),
                &token,
                request,
                65_536,
            )
        }
    }

    struct LostReplyServer {
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl LostReplyServer {
        fn finish(mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    impl Drop for LostReplyServer {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Accepts one POST and closes unanswered. Both accept and body read
    /// are bounded, and the caller owns the server's completion.
    fn lost_reply_api() -> (
        String,
        Arc<parking_lot::Mutex<Vec<String>>>,
        LostReplyServer,
    ) {
        let applied = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api_url = format!("http://{}/jmap/api", listener.local_addr().unwrap());
        let server = Arc::clone(&applied);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped.load(std::sync::atomic::Ordering::Acquire)
                            || std::time::Instant::now() >= deadline
                        {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("private JMAP accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap();
                    }
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let document: Value = serde_json::from_slice(&body).unwrap();
            server
                .lock()
                .push(document["methodCalls"][0][0].as_str().unwrap().to_owned());
        });
        (
            api_url,
            applied,
            LostReplyServer {
                stop,
                thread: Some(thread),
            },
        )
    }

    struct RecordingOnlyExchange;

    impl JmapExchange for RecordingOnlyExchange {
        fn readiness(&self) -> Result<(), TransportFault> {
            Ok(())
        }

        fn exchange(
            &self,
            _request: &JmapRequest,
            _lease: &ScopedCredentialLease,
        ) -> Result<JmapResponse, TransportFault> {
            panic!("recording an intent must not contact the provider")
        }
    }

    #[test]
    fn invalid_booking_intents_do_not_persist_or_burn_the_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("intent.sqlite");
        let ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&path).unwrap()));
        let transport = Arc::new(
            JmapCalendarTransport::new(JmapCalendarConfig {
                account_id: "account-1".to_owned(),
                calendar_id: "calendar-1".to_owned(),
                exchange: Arc::new(RecordingOnlyExchange),
            })
            .unwrap(),
        );
        let adapter = CalendarAdapter::new(
            Arc::clone(&ledger),
            transport,
            Arc::new(FileCredentialLeases::new(std::collections::BTreeMap::new())),
            "seat:recording",
        );
        let identity = EffectIdentity {
            idempotency_key: "booking-input-boundary".to_owned(),
            correlation_id: "booking-input-boundary".to_owned(),
        };
        let command_id = identity.command_id().unwrap();
        let now = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let draft = CalendarEventDraft {
            title: "Appointment".to_owned(),
            start: "2027-01-20T10:00:00Z".to_owned(),
            end: "2027-01-20T11:00:00Z".to_owned(),
            location: None,
            description: None,
        };
        let mut fractional = draft.clone();
        fractional.start = "2027-01-20T10:00:00.5Z".to_owned();
        for mutation in [
            CalendarMutation::Create(fractional),
            CalendarMutation::BatchCreate {
                drafts: vec![draft.clone(); crate::calendar::MAX_BATCH_EVENTS + 1],
            },
        ] {
            let invalid = CalendarProposal {
                account: "personal".to_owned(),
                mutation,
            };
            assert!(matches!(
                adapter.record_booking_intent(&identity, &invalid, now),
                Err(LifeError::InvalidInput(_))
            ));
            assert!(ledger.lock().command(&command_id).unwrap().is_none());
        }
        let valid = CalendarProposal {
            account: "personal".to_owned(),
            mutation: CalendarMutation::Create(draft),
        };
        adapter
            .record_booking_intent(&identity, &valid, now)
            .unwrap();
        drop(adapter);
        drop(ledger);
        let reopened = Ledger::open(&path).unwrap();
        let recorded = reopened.command(&command_id).unwrap().unwrap();
        assert_eq!(recorded.arguments, serde_json::to_value(valid).unwrap());
        assert!(recorded.terminal_status.is_none());
    }

    /// An applied `CalendarEvent/set` whose reply is lost stays accepted and
    /// unsettled, never executed:false; the replay after reopen never posts.
    #[test]
    fn jmap_booking_with_a_lost_reply_stays_in_doubt_across_reopen() {
        use odin_kernel::{
            ApprovalCommand, ApprovalDecision, ApprovalGate, ApprovalScope, ConsumeOutcome,
            DecisionOutcome, NewApproval,
        };
        let now = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("jmap.secret");
        std::fs::write(&secret, "fixture-bearer").unwrap();
        let handle = OpaqueCredentialHandle::new("cred:jmap").unwrap();
        let leases: Arc<dyn CredentialLeases> = Arc::new(FileCredentialLeases::new(
            std::collections::BTreeMap::from([(
                "personal".to_owned(),
                AccountSecretRef::new(handle, secret).unwrap(),
            )]),
        ));
        let (api_url, applied, server) = lost_reply_api();
        let transport: Arc<dyn crate::calendar::CalendarTransport> = Arc::new(
            JmapCalendarTransport::new(JmapCalendarConfig {
                account_id: "account-1".to_owned(),
                calendar_id: "calendar-1".to_owned(),
                exchange: Arc::new(DiscoveredApi { api_url }),
            })
            .unwrap(),
        );
        let ledger_path = dir.path().join("ledger.sqlite");
        let adapter_over = |ledger: &Arc<parking_lot::Mutex<Ledger>>| {
            let (transport, leases) = (Arc::clone(&transport), Arc::clone(&leases));
            CalendarAdapter::new(Arc::clone(ledger), transport, leases, "seat:e3")
        };
        let key = EffectIdentity {
            idempotency_key: "key-jmap-lost".to_owned(),
            correlation_id: "corr-jmap-lost".to_owned(),
        };
        let draft = CalendarEventDraft {
            title: "Dentist".to_owned(),
            start: "2027-01-20T10:00:00Z".to_owned(),
            end: "2027-01-20T11:00:00Z".to_owned(),
            location: None,
            description: None,
        };
        let proposal = CalendarProposal {
            account: "personal".to_owned(),
            mutation: CalendarMutation::Create(draft),
        };

        let ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&ledger_path).unwrap()));
        let adapter = adapter_over(&ledger);
        adapter.record_booking_intent(&key, &proposal, now).unwrap();
        // The host kernel gate's single consumption at the recorded
        // intent's exact scope; the adapter only verifies it.
        let command_id = key.command_id().unwrap();
        let approval_id = odin_domain::ApprovalId::new("approval:key-jmap-lost").unwrap();
        let scope = {
            let command = ledger.lock().command(&command_id).unwrap().unwrap();
            ApprovalScope {
                target_kind: command.target_kind,
                target_id: command.target_id,
                capability_id: command.capability_id,
                arguments_digest: command.arguments_hash,
            }
        };
        {
            let mut guard = ledger.lock();
            let mut gate = ApprovalGate::new(&mut guard);
            let requested = gate
                .request(NewApproval {
                    approval_id: approval_id.clone(),
                    issuer: "seat:e3".to_owned(),
                    scope: scope.clone(),
                    requested_at: now,
                    expires_at: now + time::Duration::hours(1),
                })
                .unwrap();
            let DecisionOutcome::Approved(approval) = gate
                .decide(
                    &approval_id,
                    requested.revision,
                    ApprovalDecision::Approve { evidence_ref: None },
                    "colin",
                    now,
                )
                .unwrap()
            else {
                panic!("the owner approval must settle");
            };
            let consumed = gate
                .authorize_command(
                    odin_domain::EffectClass::R3,
                    ApprovalCommand {
                        command_id: &command_id,
                        approval_id: Some(&approval_id),
                        scope: &scope,
                        expected_revision: Some(approval.revision),
                        now,
                    },
                )
                .unwrap();
            assert!(matches!(consumed, ConsumeOutcome::Consumed(_)));
        }
        let proof = HostConsumeProof {
            approval_id: Some(&approval_id),
            command_id: &command_id,
            scope: &scope,
        };
        let first = adapter.settle_booking(&key, &proof, now);
        server.finish();
        assert!(first.is_err(), "a lost reply is never a booking: {first:?}");
        assert_eq!(
            *applied.lock(),
            ["CalendarEvent/set"],
            "the provider applied the POST"
        );
        drop(adapter);
        drop(ledger);

        // Only the durable store carries the outcome across the reopen.
        let ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&ledger_path).unwrap()));
        let command = ledger.lock().command(&command_id).unwrap().unwrap();
        assert!(command.accepted_at.is_some());
        assert_eq!(
            command.terminal_result, None,
            "an applied mutation is never recorded as never executed: first={first:?}"
        );
        let replay = adapter_over(&ledger).settle_booking(&key, &proof, now);
        assert_eq!(replay, Err(LifeError::InDoubt));
        assert_eq!(
            applied.lock().len(),
            1,
            "the replay never reaches the provider"
        );
    }
}
