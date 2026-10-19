//! Loopback tests for private credentials, lease checks, IMAP framing, UIDPLUS, and CalDAV outcomes.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use odin_domain::huginn::OpaqueCredentialHandle;
use odin_domain::CapabilityId;

use odin_hermes::account::{
    AccountSecretRef, AccountUnavailable, CredentialLeases, FileCredentialLeases,
    ScopedCredentialLease, TransportFault,
};
use odin_hermes::calendar::{
    CalendarEventDraft, CalendarMutation, CalendarProposal, CalendarTransport, CalendarWindow,
    CALENDAR_PROPOSE_OPERATION, CALENDAR_READ_OPERATION,
};
use odin_hermes::generic_provider::{
    CaldavAuth, CaldavEndpoint, CaldavHttp, CaldavHttpRequest, CaldavHttpResponse,
    GenericLifeProvider, GenericProviderConfig, ImapSession, MailEndpoint, TlsMode,
};

const ACCOUNT: &str = "colin@example.com";
const SASL_USER: &str = "colin@example.com";
/// XOAUTH2 tokens cannot contain whitespace.
const TOKEN: &str = "EwAAAAm3EXAMPLE-TOKEN-BODYq9w0";
const REFRESH_TOKEN: &str = "0.AXAAA-MICROSOFT-REFRESH-GRANT";
const CLIENT_ID: &str = "9e5f94bc-e8a4-4e73-b8be-63364c29d753";
const TENANT: &str = "common";
const CALDAV_USER: &str = "colin";
const CALDAV_PASSWORD: &str = "rustical-app-token-secret";
const HANDLE: &str = "cred:test-microsoft-mail";

const NOW: time::OffsetDateTime = time::OffsetDateTime::UNIX_EPOCH;

/// The full documented bundle: the refresh quartet is required.
fn credential_json() -> String {
    format!(
        r#"{{"version":1,"account":"{ACCOUNT}","user":"{SASL_USER}","access_token":"{TOKEN}","expires_at":"2026-12-31T23:59:59Z","refresh_token":"{REFRESH_TOKEN}","client_id":"{CLIENT_ID}","tenant":"{TENANT}","caldav_basic":{{"user":"{CALDAV_USER}","password":"{CALDAV_PASSWORD}"}}}}"#
    )
}

fn write_bundle_with(
    directory: &std::path::Path,
    name: &str,
    mode: u32,
    body: String,
) -> std::path::PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, body).expect("credential file writes");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("credential permissions set");
    path
}

fn secret_for(path: &std::path::Path) -> AccountSecretRef {
    AccountSecretRef::new(
        OpaqueCredentialHandle::new(HANDLE).expect("the test handle satisfies the grammar"),
        path.to_path_buf(),
    )
    .expect("the absolute secret path is valid")
}

fn issue_lease(source: &FileCredentialLeases, capability: &'static str) -> ScopedCredentialLease {
    source
        .issue(
            &CapabilityId::new(capability).expect("the reserved capability id is valid"),
            ACCOUNT,
            NOW,
        )
        .expect("the lease issues against the real file")
}

fn lease_for(path: &std::path::Path, capability: &'static str) -> ScopedCredentialLease {
    let mut accounts = BTreeMap::new();
    accounts.insert(ACCOUNT.to_owned(), secret_for(path));
    issue_lease(&FileCredentialLeases::new(accounts), capability)
}

/// A lease bound to a different deployment's configured handle.
fn stranger_lease_for(path: &std::path::Path, capability: &'static str) -> ScopedCredentialLease {
    let mut accounts = BTreeMap::new();
    accounts.insert(
        ACCOUNT.to_owned(),
        AccountSecretRef::new(
            OpaqueCredentialHandle::new("cred:another-deployment")
                .expect("the stranger handle satisfies the grammar"),
            path.to_path_buf(),
        )
        .expect("the absolute secret path is valid"),
    );
    issue_lease(&FileCredentialLeases::new(accounts), capability)
}

fn provider_config(caldav: CaldavEndpoint, secret: AccountSecretRef) -> GenericProviderConfig {
    GenericProviderConfig {
        account: ACCOUNT.to_owned(),
        from_address: ACCOUNT.to_owned(),
        imap: MailEndpoint {
            host: "imap.example.invalid".to_owned(),
            port: 993,
            tls: TlsMode::ImplicitTls,
        },
        smtp: MailEndpoint {
            host: "smtp.example.invalid".to_owned(),
            port: 587,
            tls: TlsMode::StartTls,
        },
        helo_name: "odin.test".to_owned(),
        inbox_mailbox_id: "INBOX".to_owned(),
        drafts_mailbox_id: "Drafts".to_owned(),
        archive_mailbox_id: "Archive".to_owned(),
        trash_mailbox_id: "Trash".to_owned(),
        caldav: Some(caldav),
        credential: secret,
        request_timeout_ms: 5_000,
        max_response_bytes: 1_048_576,
    }
}

fn provider_with(
    caldav: CaldavEndpoint,
    secret: AccountSecretRef,
    seam: Arc<dyn CaldavHttp>,
) -> GenericLifeProvider {
    GenericLifeProvider::new(provider_config(caldav, secret), seam)
        .expect("the provider configuration validates")
}

/// One scripted CalDAV seam: every dispatch is recorded (its secrets
/// stay redacted in any Debug) and the scripted response — at most one
/// — is served.
struct ScriptedCaldav {
    requests: Mutex<Vec<CaldavHttpRequest>>,
    response: Mutex<Option<Result<CaldavHttpResponse, TransportFault>>>,
}

impl ScriptedCaldav {
    fn with_response(response: Result<CaldavHttpResponse, TransportFault>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(response)),
        }
    }

    fn never_dialing() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(None),
        }
    }
}

impl CaldavHttp for ScriptedCaldav {
    fn dispatch(&self, request: CaldavHttpRequest) -> Result<CaldavHttpResponse, TransportFault> {
        self.requests
            .lock()
            .expect("the request log locks")
            .push(request);
        self.response
            .lock()
            .expect("the response script locks")
            .clone()
            .expect("no calendar dispatch was expected in this test")
    }
}

/// The remote HTTPS RustiCal collection this deployment declares.
fn rustical_collection() -> CaldavEndpoint {
    CaldavEndpoint {
        base_url: "https://mini.example.test:8443/caldav".to_owned(),
        calendar_url: Some(
            "https://mini.example.test:8443/caldav/principal/colin/caltech".to_owned(),
        ),
    }
}

const UTC_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//odin-life//test//EN\r\nBEGIN:VEVENT\r\nUID:utc-event@caltech\r\nDTSTAMP:20260927T000000Z\r\nDTSTART:20261001T090000Z\r\nDTEND:20261001T100000Z\r\nSUMMARY:UTC event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// A timezone-local event: never guessed as UTC, never allowed to
/// abort the whole window read.
const TZ_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//odin-life//test//EN\r\nBEGIN:VEVENT\r\nUID:tz-event@caltech\r\nDTSTAMP:20260927T000000Z\r\nDTSTART;TZID=America/Los_Angeles:20261001T090000\r\nDTEND;TZID=America/Los_Angeles:20261001T100000\r\nSUMMARY:Zoned event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// A Caltech class as Outlook exports it: a weekly series in a Windows
/// zone name with its VTIMEZONE, as a server that does not expand
/// returns it — the master, dated its first meeting.
const CLASS_SERIES_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:Microsoft Exchange Server 2010\r\nBEGIN:VTIMEZONE\r\nTZID:Pacific Standard Time\r\nBEGIN:STANDARD\r\nDTSTART:16010101T020000\r\nTZOFFSETFROM:-0700\r\nTZOFFSETTO:-0800\r\nRRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=1SU;BYMONTH=11\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:16010101T020000\r\nTZOFFSETFROM:-0800\r\nTZOFFSETTO:-0700\r\nRRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=2SU;BYMONTH=3\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:che126-lab@caltech\r\nDTSTAMP:20260920T000000Z\r\nDTSTART;TZID=\"Pacific Standard Time\":20260928T090000\r\nDTEND;TZID=\"Pacific Standard Time\":20260928T115500\r\nRRULE:FREQ=WEEKLY;BYDAY=MO;UNTIL=20261211T000000Z\r\nSUMMARY:ChE 126: Chemical Engineering Laboratory\r\nLOCATION:Spalding 106\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// The same series expanded by the server (RFC 4791 §9.6.5): one UTC
/// instance per meeting in the window, plus an event in a zone nobody
/// knows.
const CLASS_EXPANDED_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//rustical//EN\r\nBEGIN:VEVENT\r\nUID:me295@caltech\r\nDTSTAMP:20260920T000000Z\r\nRECURRENCE-ID:20261005T200000Z\r\nDTSTART:20261005T200000Z\r\nDTEND:20261005T212500Z\r\nSUMMARY:ME/CE/AM 295: Agentic AI in Scientific Discovery\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:me295@caltech\r\nDTSTAMP:20260920T000000Z\r\nRECURRENCE-ID:20261007T200000Z\r\nDTSTART:20261007T200000Z\r\nDTEND:20261007T212500Z\r\nSUMMARY:ME/CE/AM 295: Agentic AI in Scientific Discovery\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:mars@caltech\r\nDTSTAMP:20260920T000000Z\r\nDTSTART;TZID=Olympus Mons Time:20261005T100000\r\nDTEND;TZID=Olympus Mons Time:20261005T110000\r\nSUMMARY:Unknown zone\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// Expanded series and known TZIDs produce individual meetings; out-of-window masters do not.
#[test]
fn a_caltech_class_schedule_reads_one_event_per_meeting() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = write_bundle_with(
        directory.path(),
        "microsoft-mail.json",
        0o600,
        credential_json(),
    );
    let secret = secret_for(&path);
    let response = |ics: &str| {
        format!(
            "<D:response><D:propstat><D:prop><C:calendar-data>{ics}</C:calendar-data></D:prop></D:propstat></D:response>"
        )
    };
    let in_window_master = CLASS_SERIES_ICS
        .replace("20260928T090000", "20261005T090000")
        .replace("20260928T115500", "20261005T115500")
        .replace("che126-lab@caltech", "che126-first@caltech");
    let multistatus = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">{}{}{}</D:multistatus>",
        response(CLASS_SERIES_ICS),
        response(&in_window_master),
        response(CLASS_EXPANDED_ICS),
    );
    let seam = Arc::new(ScriptedCaldav::with_response(Ok(CaldavHttpResponse {
        status: 207,
        etag: None,
        body: multistatus.into_bytes(),
    })));
    let provider = provider_with(
        rustical_collection(),
        secret,
        seam.clone() as Arc<dyn CaldavHttp>,
    );
    let lease = lease_for(&path, CALENDAR_READ_OPERATION);
    let window = CalendarWindow {
        account: ACCOUNT.to_owned(),
        start: "2026-10-05T07:00:00Z".to_owned(),
        end: "2026-10-06T07:00:00Z".to_owned(),
    };
    let summaries = provider
        .read_window(&lease, &window, NOW)
        .expect("the window reads");
    let read: Vec<(&str, &str)> = summaries
        .iter()
        .map(|event| (event.id.as_str(), event.start.as_str()))
        .collect();
    assert_eq!(
        read,
        vec![
            ("che126-first@caltech", "2026-10-05T16:00:00Z"),
            ("me295@caltech", "2026-10-05T20:00:00Z"),
        ],
        "Monday's two meetings, exactly; the 09-28 master and Wednesday's instance are outside"
    );
    let requests = seam.requests.lock().expect("the request log locks");
    let body = String::from_utf8(requests[0].body.clone().expect("a REPORT body"))
        .expect("the body is UTF-8");
    assert!(
        body.contains("<C:expand start=\"20261005T070000Z\" end=\"20261006T070000Z\"/>"),
        "the server expands series in the window: {body}"
    );
}

fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the loopback listener binds");
    let address = listener
        .local_addr()
        .expect("the listener address resolves");
    let client = TcpStream::connect(address).expect("the client connects");
    let (server, _) = listener.accept().expect("the server accepts");
    (client, server)
}

/// One scripted IMAP server step.
enum Step {
    /// Read one client command line (plus any `{N}` literal it
    /// announces), then reply.
    Command { literal: bool, reply: String },
    /// Reply without reading: the client is mid-exchange.
    Reply(String),
    /// Read one fixed-size client literal plus its trailing CRLF, then reply.
    Literal { size: usize, reply: String },
}

fn serve_scripted_imap(server: TcpStream, steps: Vec<Step>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut writer = server.try_clone().expect("the script clones the stream");
        let mut reader = BufReader::new(server);
        for step in steps {
            match step {
                Step::Reply(reply) => {
                    writer
                        .write_all(reply.as_bytes())
                        .expect("the script writes");
                }
                Step::Literal { size, reply } => {
                    let mut bytes = vec![0u8; size];
                    reader
                        .read_exact(&mut bytes)
                        .expect("the script reads the literal");
                    let mut terminator = [0u8; 2];
                    reader
                        .read_exact(&mut terminator)
                        .expect("the script reads the literal CRLF");
                    writer
                        .write_all(reply.as_bytes())
                        .expect("the script writes");
                }
                Step::Command { literal, reply } => {
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .expect("the script reads one command line");
                    if literal {
                        let open = line.rfind('{').expect("the command announces a literal");
                        let size: usize = line[open + 1..line.len() - 2]
                            .parse()
                            .expect("the literal size parses");
                        let mut bytes = vec![0u8; size];
                        reader
                            .read_exact(&mut bytes)
                            .expect("the script reads the literal");
                        let mut terminator = [0u8; 2];
                        reader
                            .read_exact(&mut terminator)
                            .expect("the script reads the literal CRLF");
                    }
                    writer
                        .write_all(reply.as_bytes())
                        .expect("the script writes");
                }
            }
        }
    })
}

#[test]
fn calendar_readiness_validates_the_same_basic_credentials_as_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = write_bundle_with(
        directory.path(),
        "credentials.json",
        0o600,
        credential_json(),
    );
    let seam = Arc::new(ScriptedCaldav::with_response(Err(TransportFault::Timeout)));
    let provider = provider_with(rustical_collection(), secret_for(&path), seam.clone());
    CalendarTransport::readiness(&provider, ACCOUNT).unwrap();
    for (field, value) in [("user", ""), ("password", ""), ("user", "invalid\u{7}user")] {
        let mut document: serde_json::Value = serde_json::from_str(&credential_json()).unwrap();
        document["caldav_basic"][field] = serde_json::Value::String(value.to_owned());
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(matches!(
            CalendarTransport::readiness(&provider, ACCOUNT),
            Err(TransportFault::Protocol(_))
        ));
        assert!(seam.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn credential_law_binds_lease_file_and_account_through_the_public_seam() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = write_bundle_with(
        directory.path(),
        "microsoft-mail.json",
        0o600,
        credential_json(),
    );
    let secret = secret_for(&path);
    let multistatus = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
         <D:response><D:propstat><D:prop><C:calendar-data>{UTC_ICS}</C:calendar-data></D:prop></D:propstat></D:response>\
         <D:response><D:propstat><D:prop><C:calendar-data>{TZ_ICS}</C:calendar-data></D:prop></D:propstat></D:response>\
         </D:multistatus>"
    );
    let seam = Arc::new(ScriptedCaldav::with_response(Ok(CaldavHttpResponse {
        status: 207,
        etag: None,
        body: multistatus.into_bytes(),
    })));
    let provider = provider_with(
        rustical_collection(),
        secret,
        seam.clone() as Arc<dyn CaldavHttp>,
    );
    let lease = lease_for(&path, CALENDAR_READ_OPERATION);
    let window = CalendarWindow {
        account: ACCOUNT.to_owned(),
        start: "2026-09-01T00:00:00Z".to_owned(),
        end: "2026-11-01T00:00:00Z".to_owned(),
    };

    let summaries = provider
        .read_window(&lease, &window, NOW)
        .expect("the window reads");
    // The UTC event is read with its exact times; the event local to a
    // zone the tz database names is converted exactly (09:00 PDT).
    assert_eq!(summaries.len(), 2, "the TZID event never aborts the window");
    assert_eq!(summaries[0].id, "utc-event@caltech");
    assert_eq!(summaries[0].start, "2026-10-01T09:00:00Z");
    assert_eq!(summaries[0].end, "2026-10-01T10:00:00Z");
    assert_eq!(summaries[1].id, "tz-event@caltech");
    assert_eq!(summaries[1].start, "2026-10-01T16:00:00Z");

    // Remote HTTPS rode the separately provisioned CalDAV Basic pair,
    // not the Microsoft bearer, and no secret value is recoverable from
    // any outward representation of the request.
    let requests = seam.requests.lock().expect("the request log locks");
    assert_eq!(requests.len(), 1);
    assert!(
        matches!(&requests[0].auth, CaldavAuth::Basic { user, .. } if user.as_str() == CALDAV_USER),
        "remote HTTPS authenticates with the CalDAV Basic pair"
    );
    let debugged = format!("{:?}", requests[0].auth);
    assert!(
        !debugged.contains(CALDAV_PASSWORD),
        "the CalDAV password stays redacted"
    );
    assert!(!debugged.contains(TOKEN), "the access token stays redacted");
    drop(requests);

    // A lease bound to another deployment's handle is refused before
    // the file is even read.
    let stranger = stranger_lease_for(&path, CALENDAR_READ_OPERATION);
    assert!(matches!(
        provider.read_window(&stranger, &window, NOW),
        Err(TransportFault::Refused(_))
    ));

    // A lease for a different capability is refused.
    let wrong_capability = lease_for(&path, "email.search");
    assert!(matches!(
        provider.read_window(&wrong_capability, &window, NOW),
        Err(TransportFault::Refused(_))
    ));

    // A window naming another account never reaches this provider.
    let other_window = CalendarWindow {
        account: "other@example.com".to_owned(),
        ..window.clone()
    };
    assert!(matches!(
        provider.read_window(&lease, &other_window, NOW),
        Err(TransportFault::Refused(_))
    ));

    // Enforce private file mode on every exchange.
    let loose = write_bundle_with(directory.path(), "loose.json", 0o644, credential_json());
    let loose_lease = lease_for(&loose, CALENDAR_READ_OPERATION);
    let loose_secret = secret_for(&loose);
    let loose_provider = provider_with(
        rustical_collection(),
        loose_secret,
        Arc::new(ScriptedCaldav::never_dialing()),
    );
    assert!(matches!(
        loose_provider.read_window(&loose_lease, &window, NOW),
        Err(TransportFault::Refused(_))
    ));

    // A bundle missing the refresh quartet never parses.
    let no_tenant = credential_json().replace(&format!("\"tenant\":\"{TENANT}\","), "");
    let incomplete = write_bundle_with(directory.path(), "incomplete.json", 0o600, no_tenant);
    let incomplete_lease = lease_for(&incomplete, CALENDAR_READ_OPERATION);
    let incomplete_provider = provider_with(
        rustical_collection(),
        secret_for(&incomplete),
        Arc::new(ScriptedCaldav::never_dialing()),
    );
    assert!(matches!(
        incomplete_provider.read_window(&incomplete_lease, &window, NOW),
        Err(TransportFault::Protocol(_))
    ));

    // Whitespace cannot appear in an XOAUTH2 token.
    let spaced = credential_json().replace(TOKEN, "EwAA AAAA BBBB");
    let spaced_path = write_bundle_with(directory.path(), "spaced.json", 0o600, spaced);
    let spaced_lease = lease_for(&spaced_path, CALENDAR_READ_OPERATION);
    let spaced_provider = provider_with(
        rustical_collection(),
        secret_for(&spaced_path),
        Arc::new(ScriptedCaldav::never_dialing()),
    );
    assert!(matches!(
        spaced_provider.read_window(&spaced_lease, &window, NOW),
        Err(TransportFault::Protocol(_))
    ));

    // None of the refusals ever reached the calendar service.
    assert_eq!(
        seam.requests.lock().expect("the request log locks").len(),
        1,
        "refused exchanges dispatch nothing"
    );
}

#[test]
fn standard_fetch_framing_parses_seq_literal_and_internaldate() {
    let (client, server) = loopback_pair();
    let literal = "Subject: wire test\r\n\r\nline1\r\nline2\r\n";
    assert_eq!(literal.len(), 36);
    let fetch_full_reply = format!(
        "* 3 FETCH (UID 7 INTERNALDATE \"27-Sep-2026 12:00:00 +0000\" BODY[] {{36}}\r\n{literal})\r\nA002 OK fetch done\r\n"
    );
    let headers_literal = "From: sender@example.com\r\n\r\n";
    assert_eq!(headers_literal.len(), 28);
    let fetch_headers_reply = format!(
        "* 3 FETCH (UID 7 INTERNALDATE \"27-Sep-2026 12:00:00 +0000\" BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)] {{28}}\r\n{headers_literal})\r\nA003 OK headers done\r\n"
    );
    let script = serve_scripted_imap(
        server,
        vec![
            Step::Reply("* OK scripted IMAP ready\r\n".to_owned()),
            Step::Command {
                literal: false,
                reply: "A001 OK select done\r\n".to_owned(),
            },
            Step::Command {
                literal: false,
                reply: fetch_full_reply,
            },
            Step::Command {
                literal: false,
                reply: fetch_headers_reply,
            },
        ],
    );
    let mut session =
        ImapSession::over_insecure_stream(client, 65_536).expect("the session starts");
    session
        .select_mailbox("INBOX")
        .expect("the mailbox selects");

    let fetched = session.uid_fetch_full(7).expect("the full fetch parses");
    let (bytes, received_at) = fetched.expect("the fetched message exists");
    assert_eq!(
        bytes,
        literal.as_bytes(),
        "the BODY[] literal arrives verbatim"
    );
    assert_eq!(
        received_at.as_deref(),
        Some("2026-09-27T12:00:00Z"),
        "the INTERNALDATE parses into an RFC 3339 instant"
    );

    let headers = session
        .uid_fetch_headers(&[7, 9])
        .expect("the header fetch parses");
    assert_eq!(headers.len(), 1, "only the UID the server returned is read");
    assert_eq!(headers[0].0, 7);
    assert_eq!(headers[0].1.as_deref(), Some("2026-09-27T12:00:00Z"));
    assert!(
        headers[0].2.starts_with(b"From: "),
        "the header literal arrives verbatim"
    );
    script.join().expect("the script completes");
}

#[test]
fn appenduid_returns_the_appended_uid_not_the_uidvalidity() {
    let (client, server) = loopback_pair();
    let script = serve_scripted_imap(
        server,
        vec![
            Step::Reply("* OK scripted IMAP ready\r\n".to_owned()),
            Step::Command {
                literal: false,
                reply: "A001 OK select done\r\n".to_owned(),
            },
            Step::Command {
                literal: false,
                reply: "+ Ready for literal data\r\n".to_owned(),
            },
            Step::Literal {
                size: b"Subject: draft\r\n\r\nbody\r\n".len(),
                reply: "A002 OK [APPENDUID 38505 144] APPEND completed\r\n".to_owned(),
            },
        ],
    );
    let mut session =
        ImapSession::over_insecure_stream(client, 65_536).expect("the session starts");
    session
        .select_mailbox("Drafts")
        .expect("the drafts mailbox selects");
    let message = b"Subject: draft\r\n\r\nbody\r\n";
    let uid = session
        .uid_append("Drafts", "\\Seen \\Draft", message)
        .expect("the append returns the UIDPLUS uid");
    assert_eq!(
        uid, 144,
        "the appended uid is APPENDUID's second token, never the uidvalidity"
    );
    script.join().expect("the script completes");
}

#[test]
fn fetch_literal_beyond_the_bound_is_rejected_not_read() {
    let (client, server) = loopback_pair();
    let script = serve_scripted_imap(
        server,
        vec![
            Step::Reply("* OK scripted IMAP ready\r\n".to_owned()),
            Step::Command {
                literal: false,
                reply: "A001 OK select done\r\n".to_owned(),
            },
            Step::Command {
                literal: false,
                reply: "* 3 FETCH (UID 7 BODY[] {999}\r\n".to_owned(),
            },
        ],
    );
    let mut session = ImapSession::over_insecure_stream(client, 64).expect("the session starts");
    session
        .select_mailbox("INBOX")
        .expect("the mailbox selects");
    let fault = session
        .uid_fetch_full(7)
        .expect_err("an oversized literal is a bound fault");
    assert!(matches!(fault, TransportFault::Protocol(_)));
    script.join().expect("the script completes");
}

#[test]
fn foreign_origin_calendar_urls_are_refused_at_configuration() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = write_bundle_with(
        directory.path(),
        "microsoft-mail.json",
        0o600,
        credential_json(),
    );
    let fault = match GenericLifeProvider::new(
        provider_config(
            CaldavEndpoint {
                base_url: "http://127.0.0.1:1080/users/colin@example.com/calendar".to_owned(),
                calendar_url: Some("https://evil.example/steal/".to_owned()),
            },
            secret_for(&path),
        ),
        Arc::new(ScriptedCaldav::never_dialing()),
    ) {
        Err(fault) => fault,
        Ok(_) => panic!("a foreign-origin collection must never validate"),
    };
    assert!(
        matches!(fault, TransportFault::Protocol(_)),
        "the base and the collection must share one origin"
    );
}

#[test]
fn mutations_stay_in_doubt_after_dispatch_and_prevalidate_batches() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = write_bundle_with(
        directory.path(),
        "microsoft-mail.json",
        0o600,
        credential_json(),
    );
    let secret = secret_for(&path);
    let lease = lease_for(&path, CALENDAR_PROPOSE_OPERATION);
    let now = NOW;

    // The one multiline prose field: a CRLF-normalized description
    // rides the PUT as an escaped RFC 5545 text value.
    let draft = CalendarEventDraft {
        title: "Shifted lecture".to_owned(),
        start: "2026-10-01T09:00:00Z".to_owned(),
        end: "2026-10-01T10:00:00Z".to_owned(),
        location: None,
        description: Some("line one\r\nline two".to_owned()),
    };

    // Post-dispatch uncertainty stays in-doubt: never a provable
    // not-dispatched failure, never a retry invitation.
    let seam = Arc::new(ScriptedCaldav::with_response(Err(
        TransportFault::Unavailable(AccountUnavailable::Service),
    )));
    let provider = provider_with(rustical_collection(), secret.clone(), seam.clone());
    let fault = provider
        .apply(
            &lease,
            &CalendarProposal {
                account: ACCOUNT.to_owned(),
                mutation: CalendarMutation::Create(draft.clone()),
            },
            now,
        )
        .expect_err("a scripted post-dispatch fault surfaces");
    assert!(
        fault.applied.is_empty(),
        "an unacknowledged create has no proved id"
    );
    assert!(
        !fault.fault.proves_not_dispatched(),
        "a dispatched mutation is never classified as not dispatched"
    );
    {
        let requests = seam.requests.lock().expect("the request log locks");
        assert_eq!(requests.len(), 1);
        let body = requests[0]
            .body
            .as_deref()
            .expect("the PUT carries the event");
        let rendered = std::str::from_utf8(body).expect("the event body is utf-8");
        assert!(
            rendered.contains("DESCRIPTION:line one\\nline two"),
            "the multiline description escapes onto the wire"
        );
    }

    // One bad draft anywhere in a batch fails before the first PUT:
    // no partial batch can ever be committed.
    let mut drafts = vec![draft];
    drafts.push(CalendarEventDraft {
        title: "Backwards".to_owned(),
        start: "2026-10-02T10:00:00Z".to_owned(),
        end: "2026-10-02T09:00:00Z".to_owned(),
        location: None,
        description: None,
    });
    let seam = Arc::new(ScriptedCaldav::never_dialing());
    let provider = provider_with(rustical_collection(), secret, seam.clone());
    provider
        .apply(
            &lease,
            &CalendarProposal {
                account: ACCOUNT.to_owned(),
                mutation: CalendarMutation::BatchCreate { drafts },
            },
            now,
        )
        .expect_err("a batch with a bad draft refuses");
    assert!(
        seam.requests
            .lock()
            .expect("the request log locks")
            .is_empty(),
        "no PUT happens before the whole batch validates"
    );
}
