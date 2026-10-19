//! Synthetic Actual Budget integration, private-data exclusion, and deterministic purchase preparation.

use std::collections::BTreeSet;
use std::sync::Arc;
use time::OffsetDateTime;

use odin_domain::{Actor, CommandId, CommandTarget, EventId, Producer, Scope, SeatId};
use odin_hermes::account::{
    AccountSecretRef, AccountUnavailable, FileCredentialLeases, LifeError, TransportFault,
};
use odin_hermes::email::{
    EmailAdapter, EmailDraft, EmailMessage, EmailSearchQuery, EmailSummary, EmailTransport,
};
use odin_hermes::finance::{
    summary_event, ActualBudget, FinanceDeployment, FinanceError, FinanceMonth, SummaryEventInit,
};
use odin_hermes::fixtures::{self, FinanceFixture};
use odin_hermes::purchase::{prepare, PurchasePrepareInit, PurchaseRequest};
use odin_ledger::Ledger;

const ISSUED_AT_MS: u64 = 1_800_000_000_123;

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn load_finance_fixture() -> FinanceFixture {
    fixtures::load(&fixture_dir())
        .expect("synthetic ODIN-02 fixtures are well-formed")
        .finance
}

fn build_budget_db(fixture: &FinanceFixture) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fixture
        .create_budget_db(&dir.path().join("db.sqlite"))
        .expect("the fixture budget database is writable");
    dir
}

/// Recomputes the expected summary from the fixture itself: alive rows in
/// the month window, summed independently of the adapter's SQL.
fn expected_totals(fixture: &FinanceFixture, month: &str) -> (i64, i64, u64) {
    let is_income = |name: &str| {
        fixture
            .categories
            .iter()
            .find(|category| category.name == name)
            .map(|category| category.is_income)
            .unwrap_or(false)
    };
    let mut income = 0_i64;
    let mut spent = 0_i64;
    let mut count = 0_u64;
    for transaction in &fixture.transactions {
        if transaction.tombstone || !transaction.date.starts_with(month) {
            continue;
        }
        count += 1;
        if is_income(&transaction.category) {
            income += transaction.amount_cents;
        } else {
            spent -= transaction.amount_cents;
        }
    }
    (income, spent, count)
}

fn prepare_init() -> PurchasePrepareInit {
    PurchasePrepareInit {
        command_id: CommandId::from_parts("cmd", ISSUED_AT_MS, "fixture").expect("command id"),
        sequence: 1,
        issued_at_ms: ISSUED_AT_MS,
        expires_at_ms: 1_800_003_600_123,
        actor: Actor::system("odin-hermes-fixture").expect("actor"),
        scope: Scope::default(),
        target: CommandTarget::Seat(SeatId::new("seat-fixture").expect("seat id")),
        producer: Producer::new("odin-hermes", "0.0.0", None).expect("producer"),
        approval_id: odin_domain::ApprovalId::from_parts("purchase", ISSUED_AT_MS, "fixture")
            .expect("approval id"),
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixture clock")
}

#[test]
fn fixture_summary_scopes_the_month_and_narrows_to_aggregates() {
    let fixture = load_finance_fixture();
    let dir = build_budget_db(&fixture);
    let deployment = FinanceDeployment::new(dir.path().join("db.sqlite")).expect("deployment");
    let budget = ActualBudget::open(&deployment).expect("the fixture budget opens");

    let month = FinanceMonth::parse(&fixture.month).expect("fixture month");
    let summary = budget
        .month_summary(month)
        .expect("the fixture month summarizes");

    let (income, spent, count) = expected_totals(&fixture, &fixture.month);
    assert_eq!(summary.income_cents, income, "income scopes the month");
    assert_eq!(summary.spent_cents, spent, "spend excludes tombstones");
    assert_eq!(summary.net_cents, income - spent);
    assert_eq!(summary.transaction_count, count);
    assert_eq!(summary.source, "actual-budget");
    let groceries = summary
        .categories
        .iter()
        .find(|category| category.name == "Groceries")
        .expect("Groceries are summarized");
    assert_eq!(groceries.budgeted_cents, 40_000);
    assert_eq!(groceries.spent_cents, -4_690);
    let subscriptions = summary
        .categories
        .iter()
        .find(|category| category.name == "Subscriptions")
        .expect("Subscriptions are summarized");
    assert_eq!(subscriptions.budgeted_cents, 6_500);
    assert_eq!(subscriptions.spent_cents, -6_998);

    // Budget-only categories retain their allocation and zero flow.
    let archive = summary
        .categories
        .iter()
        .find(|category| category.name == "Fixture Archive")
        .expect("budgeted zero-spend categories stay observable");
    assert_eq!(archive.budgeted_cents, 5_000);
    assert_eq!(archive.spent_cents, 0);

    // A different window yields that window's truth, not the fixture
    // month's: scoping is in the query, not in the caller.
    let september = FinanceMonth::parse("2026-09").expect("September");
    let september_summary = budget
        .month_summary(september)
        .expect("September summarizes");
    assert_eq!(september_summary.income_cents, 250_000);
    assert_eq!(september_summary.spent_cents, 0);
    assert_eq!(september_summary.transaction_count, 1);

    // The narrowed type carries no account-shaped field at all: the fixture
    // account names (with the planted number) exist only in the fixture.
    for category in &summary.categories {
        for account in &fixture.accounts {
            assert!(
                !category.name.contains(&account.name),
                "summary must not carry account names"
            );
        }
    }
}

#[test]
fn missing_or_foreign_budgets_report_typed_unavailable() {
    // No deployment fact at all: relative paths are refused, not guessed.
    let unconfigured = FinanceDeployment::new("state/actual/db.sqlite");
    assert!(matches!(
        unconfigured,
        Err(FinanceError::Unavailable(
            odin_hermes::finance::FinanceUnavailable::NotConfigured
        ))
    ));

    let dir = tempfile::tempdir().expect("tempdir");
    let absent = FinanceDeployment::new(dir.path().join("absent.sqlite")).expect("deployment");
    assert!(matches!(
        ActualBudget::open(&absent),
        Err(FinanceError::Unavailable(
            odin_hermes::finance::FinanceUnavailable::BudgetMissing
        ))
    ));

    let foreign = dir.path().join("foreign.sqlite");
    std::fs::write(&foreign, b"this is definitely not a sqlite database").expect("foreign file");
    let foreign = FinanceDeployment::new(foreign.as_path()).expect("deployment");
    assert!(matches!(
        ActualBudget::open(&foreign),
        Err(FinanceError::Unavailable(
            odin_hermes::finance::FinanceUnavailable::NotBudgetDatabase
        ))
    ));

    // A real database with the ledger tables but no envelope budgets is a
    // Report-type budget: typed unsupported, never a zeroed fake summary.
    let report_only = dir.path().join("report-type.sqlite");
    let connection = rusqlite::Connection::open(&report_only).expect("report db");
    connection
        .execute_batch(
            "CREATE TABLE transactions (id TEXT PRIMARY KEY);
             CREATE TABLE categories (id TEXT PRIMARY KEY);
             CREATE TABLE category_mapping (id TEXT PRIMARY KEY);
             CREATE TABLE category_groups (id TEXT PRIMARY KEY);",
        )
        .expect("report schema");
    drop(connection);
    let report_only = FinanceDeployment::new(report_only.as_path()).expect("deployment");
    assert!(matches!(
        ActualBudget::open(&report_only),
        Err(FinanceError::Unavailable(
            odin_hermes::finance::FinanceUnavailable::UnsupportedBudgetType
        ))
    ));

    // Window validation is typed too.
    assert!(matches!(
        FinanceMonth::parse("2026-13"),
        Err(FinanceError::InvalidMonth)
    ));
    assert!(matches!(
        FinanceMonth::parse("August 2026"),
        Err(FinanceError::InvalidMonth)
    ));
}

#[test]
fn planted_identifiers_never_reach_any_outgoing_envelope() {
    let fixture = load_finance_fixture();
    assert!(!fixture.planted_identifiers.is_empty());
    let dir = build_budget_db(&fixture);
    let deployment = FinanceDeployment::new(dir.path().join("db.sqlite")).expect("deployment");
    let budget = ActualBudget::open(&deployment).expect("the fixture budget opens");
    let summary = budget
        .month_summary(FinanceMonth::parse(&fixture.month).expect("fixture month"))
        .expect("the fixture month summarizes");

    let envelope = summary_event(
        &summary,
        SummaryEventInit {
            id: EventId::from_parts("evt", ISSUED_AT_MS, "finance").expect("event id"),
            sequence: 1,
            revision: 1,
            occurred_at_ms: ISSUED_AT_MS,
            actor: Actor::system("odin-hermes-fixture").expect("actor"),
            scope: Scope::default(),
            producer: Producer::new("odin-hermes", "0.0.0", None).expect("producer"),
        },
    )
    .expect("the summary envelope validates");

    assert!(envelope.validate().is_ok());
    assert_eq!(envelope.kind, "odin.finance.summary");
    assert_eq!(
        envelope.correlation.idempotency_key,
        "finance-summary:2026-08"
    );

    // The payload is exactly the allowlisted aggregate projection.
    let payload = envelope.payload.as_object().expect("payload object");
    let expected_keys: BTreeSet<&str> = [
        "month",
        "source",
        "income_cents",
        "spent_cents",
        "net_cents",
        "transaction_count",
        "categories",
    ]
    .into_iter()
    .collect();
    let actual_keys: BTreeSet<&str> = payload.keys().map(String::as_str).collect();
    assert_eq!(actual_keys, expected_keys, "payload keys are allowlisted");

    // And the whole serialized envelope — payload, correlation, everything —
    // carries no planted fixture identifier.
    let serialized = serde_json::to_string(&envelope).expect("envelope serializes");
    for planted in &fixture.planted_identifiers {
        assert!(
            !serialized.contains(planted.as_str()),
            "planted identifier {planted} must never reach an outgoing envelope"
        );
    }
}

#[test]
fn identical_requests_share_one_idempotency_key_and_exact_scope() {
    let request =
        PurchaseRequest::new("Fixture Vendor", "Fixture Gadget", 4_999, "EUR").expect("request");
    let first = prepare(&request, prepare_init()).expect("prepare");
    let second = prepare(&request, prepare_init()).expect("prepare");
    assert_eq!(first.idempotency_key, second.idempotency_key);
    assert_eq!(first.approval_id, second.approval_id);
    assert_eq!(first.command.args_hash, second.command.args_hash);
    assert_eq!(first.scope.arguments_digest, first.command.args_hash);
    assert_eq!(first.scope.capability_id.as_str(), "purchase.submit");
    assert_eq!(first.scope.target_kind, "purchase");
    assert_eq!(
        first.scope.target_id,
        first.approval_id.to_string(),
        "the durable scope binds the real consumed approval identity"
    );

    // The canonical request binds the envelope payload exactly.
    let payload = first.command.payload.as_object().expect("payload object");
    assert_eq!(payload["amount_cents"], 4_999);
    assert_eq!(payload["currency"], "EUR");
    assert_eq!(payload["vendor"], "Fixture Vendor");
    assert_eq!(payload["item"], "Fixture Gadget");

    // Invalid requests never reach an envelope.
    assert!(PurchaseRequest::new("", "item", 100, "EUR").is_err());
    assert!(PurchaseRequest::new("vendor", "item", 0, "EUR").is_err());
    assert!(PurchaseRequest::new("vendor", "item", 100, "eur").is_err());
    assert!(PurchaseRequest::new("vendor", "item", 100, "EURO").is_err());
}

/// Synthetic mailbox summaries expose previews, never full bodies.
struct FixtureMailbox {
    messages: Vec<odin_hermes::fixtures::EmailMessageFixture>,
    handle: odin_domain::huginn::OpaqueCredentialHandle,
}

impl EmailTransport for FixtureMailbox {
    /// The fixture serves in-memory messages: no local credential material.
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        Ok(())
    }

    fn search(
        &self,
        lease: &odin_hermes::account::ScopedCredentialLease,
        query: &EmailSearchQuery,
        _now: OffsetDateTime,
    ) -> Result<Vec<EmailSummary>, TransportFault> {
        // Match the credential handle before any exchange.
        if !lease.binds_handle(&self.handle) {
            return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
        }
        let text = query.text.to_lowercase();
        Ok(self
            .messages
            .iter()
            .filter(|message| {
                message.subject.to_lowercase().contains(&text)
                    || message.body.to_lowercase().contains(&text)
            })
            .map(|message| EmailSummary {
                id: message.id.clone(),
                subject: Some(message.subject.clone()),
                from: Some(message.from.clone()),
                received_at: Some(message.received_at.clone()),
                preview: Some(message.body.chars().take(48).collect()),
            })
            .collect())
    }

    fn read(
        &self,
        lease: &odin_hermes::account::ScopedCredentialLease,
        email_id: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<EmailMessage>, TransportFault> {
        if !lease.binds_handle(&self.handle) {
            return Err(TransportFault::Unavailable(AccountUnavailable::Credentials));
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
        _lease: &odin_hermes::account::ScopedCredentialLease,
        _draft: &EmailDraft,
        _now: OffsetDateTime,
    ) -> Result<odin_hermes::email::EmailDraftReceipt, TransportFault> {
        Err(TransportFault::Protocol(
            "the fixture mailbox does not dispatch sends",
        ))
    }

    fn manage(
        &self,
        _lease: &odin_hermes::account::ScopedCredentialLease,
        _management: &odin_hermes::email::EmailManagement,
        _now: OffsetDateTime,
    ) -> Result<odin_hermes::email::EmailManagementReceipt, odin_hermes::account::BatchFault> {
        Err(TransportFault::Protocol("the fixture mailbox does not manage messages").into())
    }

    fn send_draft(
        &self,
        _lease: &odin_hermes::account::ScopedCredentialLease,
        _receipt: &odin_hermes::email::EmailDraftReceipt,
        _now: OffsetDateTime,
    ) -> Result<String, TransportFault> {
        Err(TransportFault::Protocol(
            "the fixture mailbox does not dispatch sends",
        ))
    }
}

#[test]
fn email_fixture_drives_the_exported_search_adapter() {
    let all = fixtures::load(&fixture_dir()).expect("synthetic fixtures load");

    let dir = tempfile::tempdir().expect("tempdir");
    // The sops-rendered stand-in the lease issuer stat-checks; the value
    // behind the handle is never read by any test.
    let secret = dir.path().join("email-secret");
    std::fs::write(&secret, b"fixture secret material").expect("secret file");
    let handle = odin_domain::huginn::OpaqueCredentialHandle::new("cred:fixture-mail")
        .expect("opaque handle");
    let mut accounts = std::collections::BTreeMap::new();
    accounts.insert(
        "fixture-mail".to_owned(),
        AccountSecretRef::new(handle.clone(), secret).expect("account secret"),
    );

    let ledger = Ledger::open_in_memory().expect("in-memory ledger");
    let adapter = EmailAdapter::new(
        Arc::new(parking_lot::Mutex::new(ledger)),
        Arc::new(FixtureMailbox {
            messages: all.email.messages.clone(),
            handle,
        }),
        Arc::new(FileCredentialLeases::new(accounts)),
        "odin-hermes-fixture",
    );

    // The ODIN-02 subscription summary leg: searching the synthetic
    // mailbox through the exported adapter finds exactly the two
    // subscription messages, never the newsletter.
    let query = EmailSearchQuery {
        account: "fixture-mail".to_owned(),
        text: "subscription".to_owned(),
        limit: 10,
    };
    let summaries = adapter
        .search(&query, now())
        .expect("the fixture mailbox is searchable");
    let mut ids: Vec<&str> = summaries.iter().map(|s| s.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["email-001", "email-002"]);

    for summary in &summaries {
        let serialized = serde_json::to_string(summary).expect("summary serializes");
        for message in &all.email.messages {
            assert!(
                !serialized.contains(&message.body),
                "a search summary must not carry the message body"
            );
        }
        assert!(
            summary
                .preview
                .as_ref()
                .is_some_and(|p| p.chars().count() <= 48),
            "summaries carry bounded previews only"
        );
    }

    // The read leg returns the full synthetic receipt — content is the
    // point of a read.
    let message = adapter
        .read("fixture-mail", "email-001", now())
        .expect("the fixture message reads")
        .expect("email-001 exists");
    assert!(message
        .body_text
        .is_some_and(|body| body.contains("streaming subscription")));

    // An unconfigured account is typed unavailable, never an empty success.
    let unknown = EmailSearchQuery {
        account: "elsewhere".to_owned(),
        text: "subscription".to_owned(),
        limit: 10,
    };
    assert!(matches!(
        adapter.search(&unknown, now()),
        Err(LifeError::Unavailable(_))
    ));
}

#[test]
fn calendar_fixture_selects_only_reminder_flagged_fridays() {
    let all = fixtures::load(&fixture_dir()).expect("synthetic fixtures load");

    // Only reminder-flagged Friday events are candidates.
    let candidates = all
        .calendar
        .friday_reminder_candidates()
        .expect("fixture dates parse");
    let ids: Vec<&str> = candidates.iter().map(|event| event.id.as_str()).collect();
    assert_eq!(ids, ["cal-001"]);
    assert_eq!(candidates[0].date, "2026-08-21");

    // The weekday computation is real: a reminder on a Tuesday or a
    // Friday without the reminder flag is never proposed.
    let negative = odin_hermes::fixtures::CalendarFixture {
        events: vec![
            odin_hermes::fixtures::CalendarEventFixture {
                id: "tuesday-reminder".to_owned(),
                title: "Fixture Tuesday reminder".to_owned(),
                date: "2026-08-18".to_owned(),
                time: None,
                reminder: true,
            },
            odin_hermes::fixtures::CalendarEventFixture {
                id: "unflagged-friday".to_owned(),
                title: "Fixture unflagged Friday".to_owned(),
                date: "2026-08-21".to_owned(),
                time: None,
                reminder: false,
            },
        ],
    };
    assert!(negative
        .friday_reminder_candidates()
        .expect("negative fixture dates parse")
        .is_empty());
}

#[test]
fn duplicate_category_names_keep_distinct_budgets_and_flows() {
    // Categories with the same display name retain separate allocations and flows by id.
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db.sqlite");
    let connection = rusqlite::Connection::open(&db).expect("duplicate db");
    connection
        .execute_batch(
            // The exact base tables and column names a real Actual Budget
            // database carries (mirrors FinanceFixture::create_budget_db):
            // the adapter's schema gate and queries reference these
            // columns (isParent, is_income, tombstones), never a reduced
            // stand-in schema.
            "CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT,
                offbudget INTEGER DEFAULT 0,
                closed INTEGER DEFAULT 0,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE category_groups (
                id TEXT PRIMARY KEY,
                name TEXT,
                is_income INTEGER DEFAULT 0,
                sort_order REAL,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE categories (
                id TEXT PRIMARY KEY,
                name TEXT,
                is_income INTEGER DEFAULT 0,
                cat_group TEXT,
                sort_order REAL,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE category_mapping (
                id TEXT PRIMARY KEY,
                transferId TEXT
            );
            CREATE TABLE transactions (
                id TEXT PRIMARY KEY,
                isParent INTEGER DEFAULT 0,
                isChild INTEGER DEFAULT 0,
                parent_id TEXT,
                acct TEXT,
                category TEXT,
                amount INTEGER,
                description TEXT,
                notes TEXT,
                date INTEGER,
                transferred_id TEXT,
                sort_order REAL,
                cleared INTEGER DEFAULT 1,
                reconciled INTEGER DEFAULT 0,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE zero_budgets (
                id TEXT PRIMARY KEY,
                month INTEGER,
                category TEXT,
                amount INTEGER,
                carryover INTEGER DEFAULT 0,
                goal INTEGER,
                long_goal INTEGER
            );
            INSERT INTO accounts (id, name) VALUES ('acct-0', 'Fixture Duplicate Account');
            INSERT INTO category_groups (id, name, is_income) VALUES ('grp-0', 'Fixture', 0);
            INSERT INTO categories (id, name, is_income, cat_group) VALUES ('cat-a', 'Duplicate', 0, 'grp-0');
            INSERT INTO categories (id, name, is_income, cat_group) VALUES ('cat-b', 'Duplicate', 0, 'grp-0');
            INSERT INTO category_mapping (id, transferId) VALUES ('cat-a', 'cat-a');
            INSERT INTO category_mapping (id, transferId) VALUES ('cat-b', 'cat-b');
            INSERT INTO transactions (id, acct, category, amount, description, notes, date, tombstone)
                VALUES ('txn-0', 'acct-0', 'cat-a', -500, 'fixture payee', '', 20260805, 0);
            INSERT INTO zero_budgets (id, month, category, amount) VALUES ('budget-a', 202608, 'cat-a', 1000);
            INSERT INTO zero_budgets (id, month, category, amount) VALUES ('budget-b', 202608, 'cat-b', 2000);",
        )
        .expect("duplicate fixture schema");
    drop(connection);

    let deployment = FinanceDeployment::new(db.as_path()).expect("deployment");
    let budget = ActualBudget::open(&deployment).expect("the duplicate budget opens");
    let summary = budget
        .month_summary(FinanceMonth::parse("2026-08").expect("month"))
        .expect("the duplicate month summarizes");

    let duplicates: Vec<_> = summary
        .categories
        .iter()
        .filter(|category| category.name == "Duplicate")
        .collect();
    assert_eq!(duplicates.len(), 2, "each category ID is its own row");
    let mut budgets: Vec<i64> = duplicates
        .iter()
        .map(|category| category.budgeted_cents)
        .collect();
    budgets.sort_unstable();
    assert_eq!(budgets, [1_000, 2_000], "budgets stay keyed by category ID");
    let mut flows: Vec<i64> = duplicates
        .iter()
        .map(|category| category.spent_cents)
        .collect();
    flows.sort_unstable();
    assert_eq!(flows, [-500, 0], "flows stay keyed by category ID");
    assert_eq!(summary.spent_cents, 500);
}
