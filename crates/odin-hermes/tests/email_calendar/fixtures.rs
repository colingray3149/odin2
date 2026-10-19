//! Shared private fixtures for this suite; visible only to child modules here.

use odin_hermes::account::{
    AccountSecretRef, BatchFault, EffectIdentity, FileCredentialLeases, ScopedCredentialLease,
    TransportFault,
};
use odin_hermes::calendar::{
    CalendarAdapter, CalendarEventDraft, CalendarEventSummary, CalendarMutation,
    CalendarMutationReceipt, CalendarProposal, CalendarTransport, CalendarWindow,
};
use odin_hermes::email::{
    EmailAdapter, EmailDraft, EmailManagement, EmailManagementAction, EmailManagementReceipt,
    EmailMessage, EmailSearchQuery, EmailSummary, EmailTransport,
};
use odin_hermes::fixtures::{EmailMessageFixture, LifeFixtures};
use odin_hermes::jmap::{JmapExchange, JmapRequest, JmapResponse, JmapResponseCall};
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub(crate) const ACCOUNT: &str = "personal";

pub(crate) const SECRET_VALUE: &str = "bearer-fixture-9f27c4";

pub(crate) const EMAIL_CANARY: &str = "ACCT 4711-0142-9930";

const ISSUER: &str = "seat:sinmara";

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

pub(crate) fn fixtures() -> LifeFixtures {
    odin_hermes::fixtures::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures"),
    )
    .expect("life fixtures load")
}

pub(crate) fn identity(key: &str) -> EffectIdentity {
    EffectIdentity {
        idempotency_key: format!("key-{key}"),
        correlation_id: format!("corr-{key}"),
    }
}

/// The trusted backend's sops-rendered secret file, plus the lease
/// source bound to it. Issuance checks real availability; the value is
/// resolvable only through the separate resolution stage.
pub(crate) fn secret_dir() -> (tempfile::TempDir, FileCredentialLeases) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sinmara-email.secret");
    std::fs::write(&path, SECRET_VALUE).unwrap();
    let mut accounts = BTreeMap::new();
    accounts.insert(
        ACCOUNT.to_owned(),
        AccountSecretRef::new(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:sinmara-email").unwrap(),
            path.clone(),
        )
        .unwrap(),
    );
    let leases = FileCredentialLeases::new(accounts);
    (dir, leases)
}

type Call = (String, String);

/// Scripted email transport over the fixture messages. `search`
/// filters like a server would (subject or body match), `read` serves
/// fixture bodies, and every call records the lease scope it was
/// handed so the tests can assert scoping per operation.
pub(super) struct ScriptedEmail {
    calls: Mutex<Vec<Call>>,
    messages: Vec<EmailMessageFixture>,
    pub(super) read_fault: Mutex<Option<TransportFault>>,
    search_fault: Mutex<Option<TransportFault>>,
    draft_result: Result<String, TransportFault>,
    send_result: Result<String, TransportFault>,
}

impl ScriptedEmail {
    fn from_fixture(fixture: &LifeFixtures) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            messages: fixture.email.messages.clone(),
            read_fault: Mutex::new(None),
            search_fault: Mutex::new(None),
            draft_result: Ok("draft-1".to_owned()),
            send_result: Ok("submission-1".to_owned()),
        }
    }

    pub(super) fn calls(&self) -> Vec<Call> {
        self.calls.lock().clone()
    }
}

impl EmailTransport for ScriptedEmail {
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        Ok(())
    }

    fn search(
        &self,
        lease: &ScopedCredentialLease,
        query: &EmailSearchQuery,
        _now: OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        if let Some(fault) = *self.search_fault.lock() {
            return Err(fault);
        }
        let text = query.text.trim();
        let summaries = self
            .messages
            .iter()
            .filter(|message| message.body.contains(text) || message.subject.contains(text))
            .take(query.limit as usize)
            .map(|message| EmailSummary {
                id: message.id.clone(),
                subject: Some(message.subject.clone()),
                from: Some(message.from.clone()),
                received_at: Some(message.received_at.clone()),
                preview: None,
            })
            .collect();
        Ok(summaries)
    }

    fn read(
        &self,
        lease: &ScopedCredentialLease,
        email_id: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        if let Some(fault) = *self.read_fault.lock() {
            return Err(fault);
        }
        Ok(self
            .messages
            .iter()
            .find(|message| message.id == email_id)
            .map(|message| EmailMessage {
                id: message.id.clone(),
                subject: Some(message.subject.clone()),
                from: Some(message.from.clone()),
                received_at: Some(message.received_at.clone()),
                body_text: Some(message.body.clone()),
                calendar_invites: Vec::new(),
            }))
    }

    fn save_draft(
        &self,
        lease: &ScopedCredentialLease,
        _draft: &EmailDraft,
        _now: OffsetDateTime,
    ) -> Result<odin_hermes::email::EmailDraftReceipt, TransportFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        self.draft_result
            .clone()
            .map(|draft_id| odin_hermes::email::EmailDraftReceipt {
                draft_id,
                binding: odin_hermes::email::DraftContentBinding::Jmap {
                    account_id: lease.account().to_owned(),
                },
            })
    }

    fn send_draft(
        &self,
        lease: &ScopedCredentialLease,
        _receipt: &odin_hermes::email::EmailDraftReceipt,
        _now: OffsetDateTime,
    ) -> Result<String, TransportFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        self.send_result.clone()
    }

    fn manage(
        &self,
        lease: &ScopedCredentialLease,
        management: &EmailManagement,
        _now: OffsetDateTime,
    ) -> Result<EmailManagementReceipt, BatchFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        let mut email_ids: Vec<String> = Vec::new();
        for action in &management.actions {
            let id = match action {
                EmailManagementAction::Label { email_id, .. }
                | EmailManagementAction::Archive { email_id }
                | EmailManagementAction::Trash { email_id } => email_id.trim().to_owned(),
            };
            if !email_ids.contains(&id) {
                email_ids.push(id);
            }
        }
        Ok(EmailManagementReceipt { email_ids })
    }
}

/// Scripted calendar transport over the fixture events.
pub(super) struct ScriptedCalendar {
    pub(super) calls: Mutex<Vec<Call>>,
    events: Vec<CalendarEventSummary>,
    apply_fault: Mutex<Option<TransportFault>>,
}

impl ScriptedCalendar {
    fn from_fixture(fixture: &LifeFixtures) -> Self {
        let events = fixture
            .calendar
            .events
            .iter()
            .map(|event| {
                let start = format!(
                    "{}T{}:00Z",
                    event.date,
                    event.time.clone().unwrap_or_else(|| "00:00".to_owned())
                );
                let start_at = OffsetDateTime::parse(&start, &Rfc3339).unwrap();
                CalendarEventSummary {
                    id: event.id.clone(),
                    title: Some(event.title.clone()),
                    start: start.clone(),
                    end: (start_at + Duration::minutes(30)).format(&Rfc3339).unwrap(),
                    description: None,
                }
            })
            .collect();
        Self {
            calls: Mutex::new(Vec::new()),
            events,
            apply_fault: Mutex::new(None),
        }
    }
}

impl CalendarTransport for ScriptedCalendar {
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        Ok(())
    }

    fn read_window(
        &self,
        lease: &ScopedCredentialLease,
        _window: &CalendarWindow,
        _now: OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, TransportFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        Ok(self.events.clone())
    }

    fn apply(
        &self,
        lease: &ScopedCredentialLease,
        proposal: &CalendarProposal,
        _now: OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault> {
        self.calls.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        if let Some(fault) = *self.apply_fault.lock() {
            return Err(fault.into());
        }
        let event_ids = match &proposal.mutation {
            CalendarMutation::BatchCreate { drafts } => (1..=drafts.len())
                .map(|index| format!("event-{index}"))
                .collect(),
            _ => vec!["event-1".to_owned()],
        };
        Ok(CalendarMutationReceipt { event_ids })
    }
}

pub(crate) fn email_world(
    fixture: &LifeFixtures,
    leases: FileCredentialLeases,
) -> (EmailAdapter, Arc<ScriptedEmail>, Arc<Mutex<Ledger>>) {
    let transport = Arc::new(ScriptedEmail::from_fixture(fixture));
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let adapter = EmailAdapter::new(
        Arc::clone(&ledger),
        transport.clone(),
        Arc::new(leases),
        ISSUER,
    );
    (adapter, transport, ledger)
}

pub(crate) fn calendar_world(
    fixture: &LifeFixtures,
    leases: FileCredentialLeases,
) -> (CalendarAdapter, Arc<ScriptedCalendar>, Arc<Mutex<Ledger>>) {
    let transport = Arc::new(ScriptedCalendar::from_fixture(fixture));
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let adapter = CalendarAdapter::new(
        Arc::clone(&ledger),
        transport.clone(),
        Arc::new(leases),
        ISSUER,
    );
    (adapter, transport, ledger)
}

pub(crate) fn fixture_draft(fixture: &LifeFixtures, subject: &str, body: &str) -> EmailDraft {
    let first = &fixture.email.messages[0];
    EmailDraft {
        account: ACCOUNT.to_owned(),
        to: vec![first.from.clone()],
        subject: subject.to_owned(),
        body_text: body.to_owned(),
    }
}

pub(crate) fn fixture_event_draft(fixture: &LifeFixtures, index: usize) -> CalendarEventDraft {
    let event = &fixture.calendar.events[index % fixture.calendar.events.len()];
    let start = format!(
        "{}T{}:00Z",
        event.date,
        event.time.clone().unwrap_or_else(|| "09:00".to_owned())
    );
    let start_at = OffsetDateTime::parse(&start, &Rfc3339).unwrap();
    CalendarEventDraft {
        title: event.title.clone(),
        start: start.clone(),
        end: (start_at + Duration::minutes(30)).format(&Rfc3339).unwrap(),
        location: Some("Fixture Room".to_owned()),
        description: None,
    }
}

pub(crate) fn fixture_proposal(
    fixture: &LifeFixtures,
    index: usize,
    key: &str,
) -> CalendarProposal {
    let _ = key;
    CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::Create(fixture_event_draft(fixture, index)),
    }
}

/// Captures JMAP requests and returns scripted response documents.
pub(crate) struct ScriptedJmap {
    pub(super) requests: Mutex<Vec<JmapRequest>>,
    response: Mutex<Option<Result<JmapResponse, TransportFault>>>,
}

impl ScriptedJmap {
    pub(super) fn with_response(response: JmapResponse) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(Ok(response))),
        }
    }

    pub(super) fn with_fault(fault: TransportFault) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(Err(fault))),
        }
    }

    pub(super) fn last_request(&self) -> JmapRequest {
        self.requests
            .lock()
            .last()
            .cloned()
            .expect("an exchange happened")
    }
}

impl JmapExchange for ScriptedJmap {
    fn readiness(&self) -> Result<(), TransportFault> {
        Ok(())
    }

    fn exchange(
        &self,
        request: &JmapRequest,
        _lease: &ScopedCredentialLease,
    ) -> Result<JmapResponse, TransportFault> {
        self.requests.lock().push(request.clone());
        self.response.lock().clone().expect("a scripted response")
    }
}

pub(crate) fn jmap_response(entries: &[(&str, serde_json::Value, &str)]) -> JmapResponse {
    JmapResponse {
        responses: entries
            .iter()
            .map(|(name, arguments, call_id)| JmapResponseCall {
                name: (*name).to_owned(),
                arguments: arguments.clone(),
                call_id: (*call_id).to_owned(),
            })
            .collect(),
    }
}

pub(crate) fn email_transport_over(
    exchange: ScriptedJmap,
) -> (odin_hermes::email::JmapEmailTransport, Arc<ScriptedJmap>) {
    let exchange = Arc::new(exchange);
    let transport =
        odin_hermes::email::JmapEmailTransport::new(odin_hermes::email::JmapMailConfig {
            account_id: "acct-1".to_owned(),
            identity_id: "ident-1".to_owned(),
            from_address: "sinmara@example.test".to_owned(),
            drafts_mailbox_id: "drafts-1".to_owned(),
            archive_mailbox_id: "archive-1".to_owned(),
            trash_mailbox_id: "trash-1".to_owned(),
            exchange: exchange.clone(),
        })
        .unwrap();
    (transport, exchange)
}

pub(crate) fn calendar_transport_over(
    exchange: ScriptedJmap,
) -> (
    odin_hermes::calendar::JmapCalendarTransport,
    Arc<ScriptedJmap>,
) {
    let exchange = Arc::new(exchange);
    let transport = odin_hermes::calendar::JmapCalendarTransport::new(
        odin_hermes::calendar::JmapCalendarConfig {
            account_id: "acct-1".to_owned(),
            calendar_id: "cal-1".to_owned(),
            exchange: exchange.clone(),
        },
    )
    .unwrap();
    (transport, exchange)
}
