//! Google wire and account-router tests for request shapes, token refresh, redaction, and response limits.

use odin_domain::huginn::OpaqueCredentialHandle;
use odin_domain::CapabilityId;
use odin_hermes::account::{
    AccountSecretRef, AccountUnavailable, BatchFault, CredentialLeases, FileCredentialLeases,
    ScopedCredentialLease, TransportFault,
};
use odin_hermes::calendar::{
    CalendarEventDraft, CalendarMutation, CalendarMutationReceipt, CalendarProposal,
    CalendarTransport, CalendarWindow,
};
use odin_hermes::email::{
    CalendarInviteMethod, EmailDraft, EmailManagement, EmailManagementReceipt, EmailSearchQuery,
    EmailTransport, EMAIL_SEARCH_OPERATION,
};
use odin_hermes::google::{
    GoogleAccountConfig, GoogleInstalledClient, GoogleMethod, GoogleProvider, GoogleRequest,
    GoogleResponse, GoogleTokenFile, GoogleWire, GOOGLE_CALENDAR_API_URL, GOOGLE_GMAIL_API_URL,
    GOOGLE_TOKEN_URL,
};
use odin_hermes::provider::{LifeProvider, ProviderRouter};
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const ACCOUNT: &str = "personal";
const CLIENT_ID: &str = "fixture-client-id.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "fixture-client-secret";
const REFRESH: &str = "fixture-refresh-token";
const STALE_ACCESS: &str = "fixture-stale-access";
const FRESH_ACCESS: &str = "fixture-fresh-access";
const HANDLE: &str = "cred:google-test";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn response(status: u16, body: serde_json::Value) -> Result<GoogleResponse, TransportFault> {
    Ok(GoogleResponse { status, body })
}

#[derive(Default)]
struct ScriptedWire {
    calls: Mutex<Vec<GoogleRequest>>,
    responses: Mutex<VecDeque<Result<GoogleResponse, TransportFault>>>,
}

impl ScriptedWire {
    fn new(responses: Vec<Result<GoogleResponse, TransportFault>>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        })
    }

    fn calls(&self) -> Vec<GoogleRequest> {
        self.calls.lock().clone()
    }

    fn script(&self, responses: &[Result<GoogleResponse, TransportFault>]) {
        *self.responses.lock() = responses.to_vec().into();
    }
}

impl GoogleWire for ScriptedWire {
    fn call(&self, request: GoogleRequest) -> Result<GoogleResponse, TransportFault> {
        self.calls.lock().push(request);
        self.responses
            .lock()
            .pop_front()
            .expect("the scripted wire was called more times than scripted")
    }
}

/// RFC 4648 §5 base64url encode for fixture payloads.
fn b64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ALPHABET[(value >> 18) as usize & 63] as char);
        out.push(ALPHABET[(value >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(value >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[value as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// RFC 4648 §5 base64url decode to inspect a captured `raw` draft.
fn unb64url(text: &str) -> Vec<u8> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => panic!("invalid base64url fixture"),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    out
}

fn assert_redacted(text: &str) {
    for secret in [CLIENT_SECRET, REFRESH, STALE_ACCESS, FRESH_ACCESS] {
        assert!(!text.contains(secret), "a fixture secret leaked: {secret}");
    }
}

/// One provider world: a real 0600 token file written through the
/// public login-slice surface, a real lease source over it, and the
/// provider over the scripted wire.
fn world(
    expired: bool,
) -> (
    tempfile::TempDir,
    PathBuf,
    GoogleProvider,
    Arc<ScriptedWire>,
    FileCredentialLeases,
) {
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("google.token");
    let expiry = if expired {
        now() - Duration::seconds(3600)
    } else {
        now() + Duration::seconds(3600)
    };
    // The login slice parses the downloaded Desktop-client JSON.
    let client = GoogleInstalledClient::from_installed_json(&format!(
        r#"{{"installed":{{"client_id":"{CLIENT_ID}","client_secret":"{CLIENT_SECRET}","project_id":"fixture","auth_uri":"https://accounts.google.com/o/oauth2/auth"}}}}"#
    ))
    .unwrap();
    client
        .token_file(REFRESH, STALE_ACCESS, expiry)
        .unwrap()
        .write_private(&token_path)
        .unwrap();
    let mut accounts = BTreeMap::new();
    accounts.insert(
        ACCOUNT.to_owned(),
        AccountSecretRef::new(
            OpaqueCredentialHandle::new(HANDLE).unwrap(),
            token_path.clone(),
        )
        .unwrap(),
    );
    let leases = FileCredentialLeases::new(accounts);
    let wire = ScriptedWire::new(Vec::new());
    let provider = GoogleProvider::new(account_config(&token_path), wire.clone()).unwrap();
    (dir, token_path, provider, wire, leases)
}

/// The deployment facts every fixture provider binds: the documented
/// Google roots over the fixture token file.
fn account_config(token_path: &std::path::Path) -> GoogleAccountConfig {
    GoogleAccountConfig {
        account: ACCOUNT.to_owned(),
        credential: AccountSecretRef::new(
            OpaqueCredentialHandle::new(HANDLE).unwrap(),
            token_path.to_path_buf(),
        )
        .unwrap(),
        token_url: GOOGLE_TOKEN_URL.to_owned(),
        gmail_api_url: GOOGLE_GMAIL_API_URL.to_owned(),
        calendar_api_url: GOOGLE_CALENDAR_API_URL.to_owned(),
        calendar_id: "primary".to_owned(),
        request_timeout_ms: 1_000,
        max_response_bytes: 65_536,
    }
}

fn issue(
    leases: &FileCredentialLeases,
    capability: &'static str,
    account: &str,
) -> ScopedCredentialLease {
    leases
        .issue(&CapabilityId::new(capability).unwrap(), account, now())
        .unwrap()
}

fn message_metadata(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "snippet": "Quarterly invoice attached",
        "internalDate": "1800000000000",
        "payload": {
            "headers": [
                { "name": "Subject", "value": "Q3 invoice" },
                { "name": "From", "value": "Billing <billing@example.test>" },
            ],
        },
    })
}

#[test]
fn google_search_refreshes_the_token_and_proves_redaction() {
    let (_dir, token_path, provider, wire, leases) = world(true);
    wire.script(&[
        response(
            200,
            serde_json::json!({
                "access_token": FRESH_ACCESS,
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            }),
        ),
        response(
            200,
            serde_json::json!({
                "messages": [ { "id": "msg-1" }, { "id": "msg-2" } ],
                "resultSizeEstimate": 2,
            }),
        ),
        response(200, message_metadata("msg-1")),
        response(200, message_metadata("msg-2")),
    ]);
    let lease = issue(&leases, EMAIL_SEARCH_OPERATION, ACCOUNT);
    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "invoice".to_owned(),
        limit: 2,
    };
    let summaries = provider.search(&lease, &query, now()).unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].id, "msg-1");
    assert_eq!(summaries[0].subject.as_deref(), Some("Q3 invoice"));
    assert_eq!(summaries[0].from.as_deref(), Some("billing@example.test"));
    assert_eq!(
        summaries[0].preview.as_deref(),
        Some("Quarterly invoice attached")
    );
    let parsed =
        OffsetDateTime::parse(summaries[0].received_at.as_deref().unwrap(), &Rfc3339).unwrap();
    assert_eq!(parsed, now());

    let calls = wire.calls();
    // Token endpoint: documented URL, form grant, no bearer header.
    assert_eq!(calls[0].method, GoogleMethod::Post);
    assert_eq!(calls[0].url, GOOGLE_TOKEN_URL);
    assert_eq!(calls[0].bearer, None);
    assert_eq!(
        calls[0].form,
        vec![
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("refresh_token".to_owned(), REFRESH.to_owned()),
            ("client_id".to_owned(), CLIENT_ID.to_owned()),
            ("client_secret".to_owned(), CLIENT_SECRET.to_owned()),
        ]
    );
    // API: documented host/path/query, fresh bearer, per-id metadata.
    assert_eq!(calls[1].method, GoogleMethod::Get);
    assert_eq!(
        calls[1].url,
        format!("{GOOGLE_GMAIL_API_URL}/users/me/messages?q=invoice&maxResults=2")
    );
    assert_eq!(calls[1].bearer.as_deref(), Some(FRESH_ACCESS));
    assert_eq!(
        calls[2].url,
        format!("{GOOGLE_GMAIL_API_URL}/users/me/messages/msg-1?format=metadata&metadataHeaders=Subject&metadataHeaders=From")
    );
    assert_eq!(calls[3].url, format!("{GOOGLE_GMAIL_API_URL}/users/me/messages/msg-2?format=metadata&metadataHeaders=Subject&metadataHeaders=From"));

    // The token file was rewritten atomically, still mode 0600, with
    // the fresh access token and a forward expiry.
    let file = GoogleTokenFile::load(&token_path).unwrap();
    assert_eq!(file.access, FRESH_ACCESS);
    assert!(file.expiry_instant().unwrap() > now());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Redaction: no fixture secret appears in any Debug output, any
    // captured request debug, or any fault display.
    assert_redacted(&format!("{provider:?}"));
    assert_redacted(&format!("{file:?}"));
    for request in calls {
        assert_redacted(&format!("{request:?}"));
    }
    let fault = TransportFault::Protocol("static sanitized text");
    assert_redacted(&fault.to_string());
}

/// Production 10-04: "the most recent email from Caltech's registrar" was
/// answered with a 2023 hit while a Sep 29 one was in the same page. Gmail
/// documents no list order; hits come back newest first, undated last.
#[test]
fn google_search_answers_newest_first() {
    let (_dir, _token_path, provider, wire, leases) = world(true);
    let dated = |id: &str, internal_date: Option<&str>| {
        let mut message = message_metadata(id);
        match internal_date {
            Some(date) => message["internalDate"] = serde_json::json!(date),
            None => {
                message.as_object_mut().unwrap().remove("internalDate");
            }
        }
        message
    };
    wire.script(&[
        response(
            200,
            serde_json::json!({
                "access_token": FRESH_ACCESS,
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            }),
        ),
        response(
            200,
            serde_json::json!({
                "messages": [ { "id": "may-2023" }, { "id": "undated" }, { "id": "sep-2026" } ],
            }),
        ),
        response(200, dated("may-2023", Some("1684159200000"))),
        response(200, dated("undated", None)),
        response(200, dated("sep-2026", Some("1790726400000"))),
    ]);
    let lease = issue(&leases, EMAIL_SEARCH_OPERATION, ACCOUNT);
    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "from:(caltech.edu) registrar".to_owned(),
        limit: 3,
    };
    let ids: Vec<String> = provider
        .search(&lease, &query, now())
        .unwrap()
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(ids, ["sep-2026", "may-2023", "undated"]);
}

#[test]
fn google_read_decodes_mime_enforces_bounds_and_reports_absence() {
    let (_dir, _token, provider, wire, leases) = world(false);
    let body_text = "Quarterly numbers attached.";
    let invite = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:invite-42@caltech.edu\r\nSEQUENCE:3\r\nSUMMARY:Ph 1 office hours\r\nDTSTART;TZID=America/Los_Angeles:20261005T130000\r\nDTEND;TZID=America/Los_Angeles:20261005T140000\r\nORGANIZER:mailto:professor@caltech.edu\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let payload = serde_json::json!({
        "mimeType": "multipart/mixed",
        "headers": [
            { "name": "Subject", "value": "Numbers" },
            { "name": "From", "value": "Ada <ada@example.test>" },
        ],
        "parts": [
            {
                "mimeType": "multipart/alternative",
                "parts": [
                    { "mimeType": "text/plain", "body": { "data": b64url(body_text.as_bytes()) } },
                    { "mimeType": "text/html", "body": { "data": b64url(b"<p>ignored</p>") } },
                ],
            },
            {
                "filename": "invite.ics",
                "mimeType": "text/calendar",
                "body": { "data": b64url(invite) },
            },
            {
                "filename": "q3.pdf",
                "mimeType": "application/pdf",
                "body": { "attachmentId": "att-1", "size": 9000 },
            },
        ],
    });
    wire.script(&[response(
        200,
        serde_json::json!({
            "id": "msg-1",
            "internalDate": "1800000000000",
            "payload": payload,
        }),
    )]);
    let lease = issue(&leases, "email.read", ACCOUNT);
    let message = provider.read(&lease, "msg-1", now()).unwrap().unwrap();
    assert_eq!(message.body_text.as_deref(), Some(body_text));
    assert_eq!(message.subject.as_deref(), Some("Numbers"));
    assert_eq!(message.from.as_deref(), Some("ada@example.test"));
    assert_eq!(message.calendar_invites.len(), 1);
    let parsed = &message.calendar_invites[0];
    assert_eq!(parsed.method, CalendarInviteMethod::Request);
    assert_eq!(parsed.uid, "invite-42@caltech.edu");
    assert_eq!(parsed.sequence, 3);
    assert_eq!(parsed.start.as_deref(), Some("20261005T130000"));
    assert_eq!(
        parsed.start_timezone.as_deref(),
        Some("America/Los_Angeles")
    );

    // An over-bounds body is a typed bound fault with a static message.
    let huge = "x".repeat(20_001);
    wire.script(&[response(
        200,
        serde_json::json!({
            "id": "msg-2",
            "payload": { "mimeType": "text/plain", "body": { "data": b64url(huge.as_bytes()) } },
        }),
    )]);
    let fault = provider.read(&lease, "msg-2", now()).unwrap_err();
    assert_eq!(
        fault.to_string(),
        "the Google response failed its byte bound"
    );

    // An absent message is an honest empty answer.
    wire.script(&[response(404, serde_json::Value::Null)]);
    assert!(provider.read(&lease, "missing", now()).unwrap().is_none());
}

#[test]
fn google_save_draft_sends_raw_mime_and_refuses_header_breaks() {
    let (_dir, _token, provider, wire, leases) = world(false);
    wire.script(&[response(
        200,
        serde_json::json!({ "id": "draft-1", "message": { "id": "msg-raw" } }),
    )]);
    let lease = issue(&leases, "email.draft", ACCOUNT);
    let draft = EmailDraft {
        account: ACCOUNT.to_owned(),
        to: vec!["ada@example.test".to_owned()],
        subject: "Lunch".to_owned(),
        body_text: "Still on for noon?".to_owned(),
    };
    let draft_id = provider.save_draft(&lease, &draft, now()).unwrap();
    assert_eq!(draft_id.draft_id, "draft-1");
    let call = &wire.calls()[0];
    assert_eq!(call.method, GoogleMethod::Post);
    assert_eq!(call.url, format!("{GOOGLE_GMAIL_API_URL}/users/me/drafts"));
    let raw = call.json.as_ref().unwrap()["message"]["raw"]
        .as_str()
        .unwrap();
    let mime = String::from_utf8(unb64url(raw)).unwrap();
    assert!(mime.starts_with("MIME-Version: 1.0\r\nTo: ada@example.test\r\nSubject: Lunch\r\n"));

    // A line break in a header value is refused before any dispatch.
    wire.script(&[]);
    let injected = EmailDraft {
        account: ACCOUNT.to_owned(),
        to: vec!["ada@example.test".to_owned()],
        subject: "Lunch\r\nBcc: eve@example.test".to_owned(),
        body_text: "nope".to_owned(),
    };
    let fault = provider.save_draft(&lease, &injected, now()).unwrap_err();
    assert_eq!(fault.to_string(), "the draft header contains a line break");
    assert_eq!(wire.calls().len(), 1);
    // Gmail updates and submits atomically with the approved frozen MIME,
    // not the current mutable remote draft's content.
    wire.script(&[response(200, serde_json::json!({ "id": "sent-1" }))]);
    let send_lease = issue(&leases, "email.send", ACCOUNT);
    assert_eq!(
        provider.send_draft(&send_lease, &draft_id, now()).unwrap(),
        "sent-1"
    );
    let send = &wire.calls()[1];
    assert_eq!(
        send.url,
        format!("{GOOGLE_GMAIL_API_URL}/users/me/drafts/send")
    );
    assert_eq!(send.json.as_ref().unwrap()["id"], "draft-1");
    assert_eq!(send.json.as_ref().unwrap()["message"]["raw"], raw);
    let wrong_backend = odin_hermes::email::EmailDraftReceipt {
        draft_id: "draft-1".into(),
        binding: odin_hermes::email::DraftContentBinding::Jmap {
            account_id: ACCOUNT.into(),
        },
    };
    assert!(matches!(
        provider.send_draft(&send_lease, &wrong_backend, now()),
        Err(TransportFault::Refused(_))
    ));
    assert_eq!(wire.calls().len(), 2);
}

#[test]
fn google_calendar_apply_builds_documented_requests() {
    let (_dir, _token, provider, wire, leases) = world(false);
    wire.script(&[
        response(200, serde_json::json!({ "id": "evt-created" })),
        response(200, serde_json::json!({ "id": "evt-7" })),
        response(
            200,
            serde_json::json!({ "id": "evt-8", "status": "cancelled" }),
        ),
    ]);
    let lease = issue(&leases, "calendar.propose", ACCOUNT);
    let account = ACCOUNT.to_owned();
    let receipt = provider
        .apply(
            &lease,
            &CalendarProposal {
                account: account.clone(),
                mutation: CalendarMutation::Create(CalendarEventDraft {
                    title: "Dentist".to_owned(),
                    start: "2027-01-20T10:00:00Z".to_owned(),
                    end: "2027-01-20T11:00:00Z".to_owned(),
                    location: Some("Praxis".to_owned()),
                    description: None,
                }),
            },
            now(),
        )
        .unwrap();
    assert_eq!(receipt.event_ids, vec!["evt-created"]);
    let receipt = provider
        .apply(
            &lease,
            &CalendarProposal {
                account: account.clone(),
                mutation: CalendarMutation::Move {
                    event_id: "evt-7".to_owned(),
                    start: "2027-01-21T10:00:00Z".to_owned(),
                    end: "2027-01-21T11:00:00Z".to_owned(),
                },
            },
            now(),
        )
        .unwrap();
    assert_eq!(receipt.event_ids, vec!["evt-7"]);
    let receipt = provider
        .apply(
            &lease,
            &CalendarProposal {
                account,
                mutation: CalendarMutation::Cancel {
                    event_id: "evt-8".to_owned(),
                },
            },
            now(),
        )
        .unwrap();
    assert_eq!(receipt.event_ids, vec!["evt-8"]);

    let calls = wire.calls();
    // Create: documented collection URL, event resource body.
    assert_eq!(calls[0].method, GoogleMethod::Post);
    assert_eq!(
        calls[0].url,
        format!("{GOOGLE_CALENDAR_API_URL}/calendars/primary/events")
    );
    assert_eq!(calls[0].json.as_ref().unwrap()["summary"], "Dentist");
    assert_eq!(
        calls[0].json.as_ref().unwrap()["start"]["dateTime"],
        "2027-01-20T10:00:00Z"
    );
    // Move: PATCH of the event resource with the new absolute window.
    assert_eq!(calls[1].method, GoogleMethod::Patch);
    assert_eq!(
        calls[1].url,
        format!("{GOOGLE_CALENDAR_API_URL}/calendars/primary/events/evt-7")
    );
    assert_eq!(
        calls[1].json.as_ref().unwrap()["end"]["dateTime"],
        "2027-01-21T11:00:00Z"
    );
    // Cancel: the documented status transition, never a destroy.
    assert_eq!(calls[2].method, GoogleMethod::Patch);
    assert_eq!(
        calls[2].url,
        format!("{GOOGLE_CALENDAR_API_URL}/calendars/primary/events/evt-8")
    );
    assert_eq!(calls[2].json.as_ref().unwrap()["status"], "cancelled");
    for call in &calls {
        assert_eq!(call.bearer.as_deref(), Some(STALE_ACCESS));
        assert!(call.form.is_empty());
    }

    // An empty batch is out of bounds before any dispatch.
    let fault = provider
        .apply(
            &lease,
            &CalendarProposal {
                account: ACCOUNT.to_owned(),
                mutation: CalendarMutation::BatchCreate { drafts: vec![] },
            },
            now(),
        )
        .unwrap_err();
    assert_eq!(fault.to_string(), "the request is out of bounds");
}

#[derive(Default)]
struct Counts {
    email: Mutex<usize>,
    calendar: Mutex<usize>,
}

struct CountingProvider {
    account: &'static str,
    counts: Arc<Counts>,
}

struct CountingEmail(Arc<Counts>);

impl EmailTransport for CountingEmail {
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        Ok(())
    }

    fn search(
        &self,
        _lease: &ScopedCredentialLease,
        _query: &EmailSearchQuery,
        _now: OffsetDateTime,
    ) -> Result<Vec<odin_hermes::email::EmailSummary>, TransportFault> {
        *self.0.email.lock() += 1;
        Ok(vec![])
    }

    fn read(
        &self,
        _lease: &ScopedCredentialLease,
        _email_id: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<odin_hermes::email::EmailMessage>, TransportFault> {
        *self.0.email.lock() += 1;
        Ok(None)
    }

    fn save_draft(
        &self,
        _lease: &ScopedCredentialLease,
        _draft: &EmailDraft,
        _now: OffsetDateTime,
    ) -> Result<odin_hermes::email::EmailDraftReceipt, TransportFault> {
        *self.0.email.lock() += 1;
        Ok(odin_hermes::email::EmailDraftReceipt {
            draft_id: "draft-1".into(),
            binding: odin_hermes::email::DraftContentBinding::Jmap {
                account_id: "fixture".into(),
            },
        })
    }

    fn send_draft(
        &self,
        _lease: &ScopedCredentialLease,
        _receipt: &odin_hermes::email::EmailDraftReceipt,
        _now: OffsetDateTime,
    ) -> Result<String, TransportFault> {
        *self.0.email.lock() += 1;
        Ok("sent-1".to_owned())
    }

    fn manage(
        &self,
        _lease: &ScopedCredentialLease,
        _management: &EmailManagement,
        _now: OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault> {
        *self.0.email.lock() += 1;
        Ok(EmailManagementReceipt {
            email_ids: vec!["msg-1".to_owned()],
        })
    }
}

struct CountingCalendar(Arc<Counts>);

impl CalendarTransport for CountingCalendar {
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        Ok(())
    }

    fn read_window(
        &self,
        _lease: &ScopedCredentialLease,
        _window: &CalendarWindow,
        _now: OffsetDateTime,
    ) -> Result<Vec<odin_hermes::calendar::CalendarEventSummary>, TransportFault> {
        *self.0.calendar.lock() += 1;
        Ok(vec![])
    }

    fn apply(
        &self,
        _lease: &ScopedCredentialLease,
        _proposal: &CalendarProposal,
        _now: OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault> {
        *self.0.calendar.lock() += 1;
        Ok(CalendarMutationReceipt {
            event_ids: vec!["evt-1".to_owned()],
        })
    }
}

impl LifeProvider for CountingProvider {
    fn email_transport(&self, account: &str) -> Option<Arc<dyn EmailTransport>> {
        (account == self.account)
            .then(|| Arc::new(CountingEmail(Arc::clone(&self.counts))) as Arc<dyn EmailTransport>)
    }

    fn calendar_transport(&self, account: &str) -> Option<Arc<dyn CalendarTransport>> {
        (account == self.account).then(|| {
            Arc::new(CountingCalendar(Arc::clone(&self.counts))) as Arc<dyn CalendarTransport>
        })
    }
}

#[test]
fn router_delegates_by_account_and_refuses_foreign_leases() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("router.secret");
    std::fs::write(&secret, b"router-fixture").unwrap();
    let reference = || {
        AccountSecretRef::new(
            OpaqueCredentialHandle::new("cred:router").unwrap(),
            secret.clone(),
        )
        .unwrap()
    };
    let mut accounts = BTreeMap::new();
    accounts.insert("personal".to_owned(), reference());
    accounts.insert("work".to_owned(), reference());
    let leases = FileCredentialLeases::new(accounts);

    let personal = Arc::new(Counts::default());
    let work = Arc::new(Counts::default());
    let mut router = ProviderRouter::new();
    router.bind(
        "personal",
        Arc::new(CountingProvider {
            account: "personal",
            counts: Arc::clone(&personal),
        }),
    );
    router.bind(
        "work",
        Arc::new(CountingProvider {
            account: "work",
            counts: Arc::clone(&work),
        }),
    );

    let lease_personal = issue(&leases, EMAIL_SEARCH_OPERATION, "personal");
    let lease_work = issue(&leases, EMAIL_SEARCH_OPERATION, "work");
    let query = |account: &str| EmailSearchQuery {
        account: account.to_owned(),
        text: "hello".to_owned(),
        limit: 5,
    };

    router
        .search(&lease_personal, &query("personal"), now())
        .unwrap();
    assert_eq!(*personal.email.lock(), 1);
    assert_eq!(*work.email.lock(), 0);
    router.search(&lease_work, &query("work"), now()).unwrap();
    assert_eq!(*work.email.lock(), 1);

    // A lease bound to another account is refused before delegation.
    let fault = router
        .search(&lease_personal, &query("work"), now())
        .unwrap_err();
    assert!(matches!(fault, TransportFault::Refused(_)));
    assert_eq!(*work.email.lock(), 1);

    // An unbound account is typed unavailable, never guessed.
    let fault = router
        .search(&lease_personal, &query("missing"), now())
        .unwrap_err();
    assert!(matches!(
        fault,
        TransportFault::Unavailable(AccountUnavailable::Account)
    ));

    // Calendar delegation routes by the proposal's account.
    let proposal = CalendarProposal {
        account: "work".to_owned(),
        mutation: CalendarMutation::Cancel {
            event_id: "evt-9".to_owned(),
        },
    };
    let receipt = router.apply(&lease_work, &proposal, now()).unwrap();
    assert_eq!(receipt.event_ids, vec!["evt-1"]);
    assert_eq!(*work.calendar.lock(), 1);
    assert_eq!(*personal.calendar.lock(), 0);
}

/// Bodyless POSTs require Content-Length: 0; non-JSON HTTP refusals retain their status.
#[test]
fn a_bodiless_post_carries_content_length_and_refusals_are_typed() {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/trash", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for answer_html in [false, true] {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut has_length = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.to_ascii_lowercase().starts_with("content-length:") {
                    has_length = true;
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut stream = stream;
            let response = if !has_length || answer_html {
                "HTTP/1.1 411 Length Required\r\nContent-Type: text/html\r\nContent-Length: 15\r\n\r\n<html>411</html"
                    .to_owned()
            } else {
                let body = r#"{"id":"m1"}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            };
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    let wire = odin_hermes::google::HttpsGoogleWire::new(2_000, 65_536);
    let request = || odin_hermes::google::GoogleRequest {
        method: GoogleMethod::Post,
        url: url.clone(),
        bearer: None,
        json: None,
        form: Vec::new(),
    };
    let ok = wire.call(request()).expect("a bodiless POST is accepted");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.body["id"], "m1");
    wire.call(request()).expect_err("an HTML refusal");
    server.join().unwrap();
}

/// The real HTTPS wire with only the Calendar root moved onto a loopback
/// fixture; every exchange is counted before it leaves.
struct LoopbackCalendar {
    real: odin_hermes::google::HttpsGoogleWire,
    origin: String,
    calls: Mutex<usize>,
}

impl GoogleWire for LoopbackCalendar {
    fn call(&self, mut request: GoogleRequest) -> Result<GoogleResponse, TransportFault> {
        let Some(path) = request.url.strip_prefix(GOOGLE_CALENDAR_API_URL) else {
            return Err(TransportFault::Unavailable(AccountUnavailable::Service));
        };
        *self.calls.lock() += 1;
        request.url = format!("{}{path}", self.origin);
        self.real.call(request)
    }
}

const APPLIED: &str = "evt-applied-1";

/// A private Calendar that accepts exactly one request and applies it,
/// then stops listening before it answers, so any later dial is refused
/// for real. With `reply` the answer is written; without it the
/// connection drops with no reply at all.
fn one_shot_calendar(
    reply: bool,
) -> (String, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let created = Arc::new(Mutex::new(Vec::<String>::new()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}/calendar/v3", listener.local_addr().unwrap());
    let calendar = Arc::clone(&created);
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "calendar fixture received no request"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("calendar fixture accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
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
        calendar.lock().push(APPLIED.to_owned());
        drop(listener);
        if reply {
            let reply = format!(r#"{{"id":"{APPLIED}"}}"#);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{reply}",
                reply.len()
            )
            .unwrap();
        }
    });
    (origin, created, server)
}

/// Loopback Calendar with production provider and wire implementations plus fixture leases.
struct BookingWorld {
    _dir: tempfile::TempDir,
    provider: GoogleProvider,
    wire: Arc<LoopbackCalendar>,
    lease: ScopedCredentialLease,
}

impl BookingWorld {
    fn new(origin: String) -> Self {
        let (dir, token_path, _, _, leases) = world(false);
        let wire = Arc::new(LoopbackCalendar {
            real: odin_hermes::google::HttpsGoogleWire::new(1_000, 65_536),
            origin,
            calls: Mutex::new(0),
        });
        Self {
            provider: GoogleProvider::new(account_config(&token_path), wire.clone()).unwrap(),
            wire,
            lease: issue(&leases, "calendar.propose", ACCOUNT),
            _dir: dir,
        }
    }
}

fn event_draft(title: &str, hour: u8) -> CalendarEventDraft {
    CalendarEventDraft {
        title: title.to_owned(),
        start: format!("2027-01-20T{hour:02}:00:00Z"),
        end: format!("2027-01-20T{:02}:00:00Z", hour + 1),
        location: None,
        description: None,
    }
}

/// A batch booking whose second member meets genuine unavailability after
/// the first member applied upstream reports the applied id beside the
/// fault, so the effect can never settle as never executed. The second
/// POST is refused by the real wire rather than by a script.
#[test]
fn a_batch_stopped_after_an_applied_member_reports_the_applied_id() {
    let (origin, created, server) = one_shot_calendar(true);
    let world = BookingWorld::new(origin);
    let proposal = CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::BatchCreate {
            drafts: vec![event_draft("Dentist", 10), event_draft("Physio", 14)],
        },
    };

    let first = world.provider.apply(&world.lease, &proposal, now());
    server.join().expect("the owned calendar fixture exits");
    assert_eq!(
        *created.lock(),
        [APPLIED],
        "the first member applied upstream"
    );
    assert_eq!(
        *world.wire.calls.lock(),
        2,
        "the second member reached the wire"
    );
    let fault = first.expect_err("a partial batch is never a booking");
    assert_eq!(
        fault.applied,
        [APPLIED],
        "the applied member's id travels with the fault"
    );
    assert_redacted(&format!("{fault:?}"));
}

/// A single booking the provider applied whose reply is lost — the peer
/// closes without answering — is never "unavailable": the real wire
/// reports a fault that does not prove the booking never dispatched, so
/// the effect stays in-doubt rather than recorded as never executed.
#[test]
fn a_lost_booking_reply_never_proves_the_booking_absent() {
    let (origin, created, server) = one_shot_calendar(false);
    let world = BookingWorld::new(origin);
    let proposal = CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::Create(event_draft("Dentist", 10)),
    };

    let first = world.provider.apply(&world.lease, &proposal, now());
    server.join().expect("the owned calendar fixture exits");
    assert_eq!(
        *created.lock(),
        [APPLIED],
        "the provider applied the booking"
    );
    assert_eq!(*world.wire.calls.lock(), 1);
    let fault = first.expect_err("a lost reply is never a booking");
    assert!(fault.applied.is_empty());
    assert!(
        !fault.fault.proves_not_dispatched(),
        "a lost reply never proves the booking absent: {fault:?}"
    );
}
