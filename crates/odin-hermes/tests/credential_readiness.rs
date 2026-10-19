//! Credential readiness through file-backed leases, runtime preflight, and canonical capability schemas.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use odin_domain::knowledge::ToolSchema;
use odin_domain::Scope;
use odin_hermes::account::{
    AccountSecretRef, AccountUnavailable, CredentialLeases, FileCredentialLeases, LeaseRejection,
    LifeError,
};
use odin_hermes::config::{HermesSettings, LifeAccountSettings, LifeProviderSettings};
use odin_hermes::runtime::{hermes_host_tools, HermesLedgers, HermesRuntime};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use odin_omp::host_tools::{HostTool, HostToolError};

const ACCOUNT: &str = "sinmara";
const SECRET_VALUE: &str = "test-rendered-credential-material";

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

fn capability(name: &str) -> odin_domain::CapabilityId {
    odin_domain::CapabilityId::new(name).expect("fixture capability id")
}

fn secret_ref(path: &Path) -> AccountSecretRef {
    AccountSecretRef::new(
        odin_domain::huginn::OpaqueCredentialHandle::new("cred:sinmara-email").unwrap(),
        path.to_path_buf(),
    )
    .unwrap()
}

/// One composed runtime over a temp state dir with the email (and
/// optionally calendar) adapter configured against `secret_path`. No
/// Discord, vault, or finance deployment is declared; the JMAP exchange
/// endpoint is unreachable. A temporary real adapter produces a bound draft
/// through the existing scripted JMAP seam before readiness is exercised.
fn runtime_with_email(
    dir: &Path,
    calendar: bool,
    secret_path: &Path,
) -> (Arc<HermesRuntime>, String) {
    let accounts = vec![LifeAccountSettings {
        account: ACCOUNT.to_owned(),
        secret_handle: "cred:sinmara-email".to_owned(),
        secret_path: secret_path.to_path_buf(),
        provider: LifeProviderSettings::Jmap {
            session_url: "https://jmap.example.invalid/session".to_owned(),
            identity_id: "identity-1".to_owned(),
            from_address: "sinmara@example.invalid".to_owned(),
            drafts_mailbox_id: "drafts".to_owned(),
            archive_mailbox_id: "archive".to_owned(),
            trash_mailbox_id: "trash".to_owned(),
            calendar_id: calendar.then(|| "calendar-1".to_owned()),
            request_timeout_ms: 1_000,
            max_response_bytes: 65_536,
        },
    }];
    let settings = HermesSettings::new(dir.join("state"), None, None, None, accounts).unwrap();
    struct DraftExchange;
    impl odin_hermes::jmap::JmapExchange for DraftExchange {
        fn readiness(&self) -> Result<(), odin_hermes::account::TransportFault> {
            Ok(())
        }

        fn exchange(
            &self,
            request: &odin_hermes::jmap::JmapRequest,
            _lease: &odin_hermes::account::ScopedCredentialLease,
        ) -> Result<odin_hermes::jmap::JmapResponse, odin_hermes::account::TransportFault> {
            assert_eq!(request.method_calls[0].name, "Email/set");
            Ok(odin_hermes::jmap::JmapResponse {
                responses: vec![odin_hermes::jmap::JmapResponseCall {
                    name: "Email/set".into(),
                    call_id: "s".into(),
                    arguments: serde_json::json!({"created":{"draft":{"id":"draft-1"}}}),
                }],
            })
        }
    }
    let adapter_ledger = Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap()));
    let transport =
        odin_hermes::email::JmapEmailTransport::new(odin_hermes::email::JmapMailConfig {
            account_id: "account-1".into(),
            identity_id: "identity-1".into(),
            from_address: "sinmara@example.invalid".into(),
            drafts_mailbox_id: "drafts".into(),
            archive_mailbox_id: "archive".into(),
            trash_mailbox_id: "trash".into(),
            exchange: Arc::new(DraftExchange),
        })
        .unwrap();
    let leases = Arc::new(FileCredentialLeases::new(BTreeMap::from([(
        ACCOUNT.to_owned(),
        secret_ref(secret_path),
    )])));
    let producer = odin_hermes::email::EmailAdapter::new(
        adapter_ledger.clone(),
        Arc::new(transport),
        leases,
        "fixture",
    );
    let receipt = producer
        .save_draft(
            &odin_hermes::account::EffectIdentity {
                idempotency_key: "readiness-draft".into(),
                correlation_id: "readiness-draft".into(),
            },
            &odin_hermes::email::EmailDraft {
                account: ACCOUNT.into(),
                to: vec!["to@example.invalid".into()],
                subject: "Approved".into(),
                body_text: "Approved body".into(),
            },
            now(),
        )
        .unwrap();
    let digest = receipt.result["draftDigest"].as_str().unwrap().to_owned();
    let runtime = HermesRuntime::open(
        settings,
        HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: adapter_ledger,
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &BTreeMap::new(),
        None,
        8_192,
        BTreeMap::new(),
        None,
    )
    .unwrap();
    (runtime, digest)
}

/// A faithful contract for the preflight seam; the CapabilityTool gate
/// observes the contract shape the shared dispatch hands it.
fn email_send_contract() -> CapabilityContract {
    CapabilityContract {
        id: capability("email.send"),
        delegate_to: None,
        version: 1,
        tool_name: odin_domain::knowledge::ToolName::new("email_send").unwrap(),
        description: "fixture contract".to_owned(),
        handler: odin_kernel::HandlerBinding::Builtin {
            name: "email_send".to_owned(),
        },
        input_schema_ref: "schemas/capability/email.send.input.json".to_owned(),
        output_schema_ref: "schemas/capability/email.send.output.json".to_owned(),
        effect_class: odin_domain::EffectClass::R3,
        seat_tags: std::collections::BTreeSet::new(),
        timeout_seconds: std::num::NonZeroU32::new(30).unwrap(),
        idempotency: odin_kernel::IdempotencyPolicy::Required,
        retry: odin_kernel::RetryPolicy { max_attempts: 1 },
        approval: odin_kernel::ApprovalRequirement::Operator,
        evidence_extractor: odin_kernel::HandlerBinding::Builtin {
            name: "odin_hermes_email_send_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

fn tool<'a>(tools: &'a [Arc<dyn HostTool>], name: &str) -> &'a Arc<dyn HostTool> {
    tools
        .iter()
        .find(|tool| tool.definition().name == name)
        .unwrap_or_else(|| panic!("{name} must be registered"))
}

/// Availability resolution refuses the exact prerequisites `issue`
/// refuses — unknown account, missing file, malformed (non-regular)
/// material — while issuing no lease, writing no state, and touching no
/// provider. `issue` reuses the same resolution, so the two can never
/// drift.
#[test]
fn availability_resolution_is_effect_free_and_shared_with_issue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sinmara-email.secret");
    std::fs::write(&path, SECRET_VALUE).unwrap();
    let leases =
        FileCredentialLeases::new(BTreeMap::from([(ACCOUNT.to_owned(), secret_ref(&path))]));
    let probe = capability("email.search");

    // Unknown account: typed identically at every seam, no lease minted.
    assert_eq!(
        leases.resolve_availability("nobody"),
        Err(LeaseRejection::UnknownAccount)
    );
    assert_eq!(
        leases.availability("nobody"),
        Err(LeaseRejection::UnknownAccount)
    );
    assert!(leases.issue(&probe, "nobody", now()).is_err());

    // Healthy material: availability observes without consuming anything —
    // the file bytes are untouched and a real lease still issues after.
    assert_eq!(leases.resolve_availability(ACCOUNT), Ok(()));
    assert_eq!(leases.availability(ACCOUNT), Ok(()));
    assert_eq!(leases.availability(ACCOUNT), Ok(()));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        SECRET_VALUE,
        "availability must never write credential material"
    );
    let lease = leases.issue(&probe, ACCOUNT, now()).unwrap();
    lease
        .admits(&probe, ACCOUNT, now())
        .expect("the issued lease binds the probe scope");
    assert!(leases.issue(&probe, ACCOUNT, now()).is_ok());

    // The use-time recheck is real: material that disappears after a
    // successful observation refuses issuance deterministically.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        leases.resolve_availability(ACCOUNT),
        Err(LeaseRejection::CredentialsUnavailable)
    );
    assert_eq!(
        leases.availability(ACCOUNT),
        Err(LeaseRejection::CredentialsUnavailable)
    );
    assert!(leases.issue(&probe, ACCOUNT, now()).is_err());

    // Malformed material: a directory where the secret file belongs is
    // not a credential file.
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        leases.resolve_availability(ACCOUNT),
        Err(LeaseRejection::CredentialsUnavailable)
    );
    assert!(leases.issue(&probe, ACCOUNT, now()).is_err());
}

/// The life adapters surface the same typed unavailability through
/// `credential_readiness` — the seam the tool gates observe — without
/// issuing a lease or reaching any transport exchange; this transport
/// holds no local credential material of its own.
#[test]
fn adapters_report_typed_credential_readiness() {
    use odin_hermes::calendar::{CalendarAdapter, CalendarTransport};
    use odin_hermes::email::{EmailAdapter, EmailTransport};

    struct NoTransport;
    impl EmailTransport for NoTransport {
        fn readiness(&self, _account: &str) -> Result<(), odin_hermes::account::TransportFault> {
            Ok(())
        }
        fn search(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _query: &odin_hermes::email::EmailSearchQuery,
            _now: time::OffsetDateTime,
        ) -> Result<Vec<odin_hermes::email::EmailSummary>, odin_hermes::account::TransportFault>
        {
            panic!("readiness must never reach the transport")
        }
        fn read(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _email_id: &str,
            _now: time::OffsetDateTime,
        ) -> Result<Option<odin_hermes::email::EmailMessage>, odin_hermes::account::TransportFault>
        {
            panic!("readiness must never reach the transport")
        }
        fn save_draft(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _draft: &odin_hermes::email::EmailDraft,
            _now: time::OffsetDateTime,
        ) -> Result<odin_hermes::email::EmailDraftReceipt, odin_hermes::account::TransportFault>
        {
            panic!("readiness must never reach the transport")
        }
        fn send_draft(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _receipt: &odin_hermes::email::EmailDraftReceipt,
            _now: time::OffsetDateTime,
        ) -> Result<String, odin_hermes::account::TransportFault> {
            panic!("readiness must never reach the transport")
        }
        fn manage(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _management: &odin_hermes::email::EmailManagement,
            _now: time::OffsetDateTime,
        ) -> Result<odin_hermes::email::EmailManagementReceipt, odin_hermes::account::BatchFault>
        {
            panic!("readiness must never reach the transport")
        }
    }
    impl CalendarTransport for NoTransport {
        fn readiness(&self, _account: &str) -> Result<(), odin_hermes::account::TransportFault> {
            Ok(())
        }
        fn read_window(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _window: &odin_hermes::calendar::CalendarWindow,
            _now: time::OffsetDateTime,
        ) -> Result<
            Vec<odin_hermes::calendar::CalendarEventSummary>,
            odin_hermes::account::TransportFault,
        > {
            panic!("readiness must never reach the transport")
        }
        fn apply(
            &self,
            _lease: &odin_hermes::account::ScopedCredentialLease,
            _proposal: &odin_hermes::calendar::CalendarProposal,
            _now: time::OffsetDateTime,
        ) -> Result<odin_hermes::calendar::CalendarMutationReceipt, odin_hermes::account::BatchFault>
        {
            panic!("readiness must never reach the transport")
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sinmara-email.secret");
    let leases: Arc<dyn CredentialLeases> =
        Arc::new(FileCredentialLeases::new(BTreeMap::from([(
            ACCOUNT.to_owned(),
            secret_ref(&path),
        )])));
    let ledger = || Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap()));
    let email = EmailAdapter::new(ledger(), Arc::new(NoTransport), Arc::clone(&leases), "test");
    let calendar =
        CalendarAdapter::new(ledger(), Arc::new(NoTransport), Arc::clone(&leases), "test");

    // Missing material reports the typed credential unavailability —
    // not a transport fault, not a lease refusal.
    let email_error = email.credential_readiness(ACCOUNT).unwrap_err();
    assert!(matches!(
        email_error,
        LifeError::Unavailable(AccountUnavailable::Credentials)
    ));
    let calendar_error = calendar.credential_readiness(ACCOUNT).unwrap_err();
    assert!(matches!(
        calendar_error,
        LifeError::Unavailable(AccountUnavailable::Credentials)
    ));
    let account_error = email.credential_readiness("nobody").unwrap_err();
    assert!(matches!(
        account_error,
        LifeError::Unavailable(AccountUnavailable::Account)
    ));

    // Healthy material reads ready — still with no transport contact.
    std::fs::write(&path, SECRET_VALUE).unwrap();
    email.credential_readiness(ACCOUNT).unwrap();
    calendar.credential_readiness(ACCOUNT).unwrap();
}

/// The shared declared-admissibility gate of every email/calendar tool
/// observes the REAL credential availability: a composed adapter whose
/// credential file is missing refuses the gate — for the plain tools and
/// for BOTH R3 phases — before anything could be journaled, minted, or
/// consumed, and the refusal is the one plain typed sentence. With
/// healthy material the same gates admit the business request.
#[test]
fn tool_gates_observe_real_credential_availability() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sinmara-email.secret");
    std::fs::write(&path, SECRET_VALUE).unwrap();
    let (runtime, draft_digest) = runtime_with_email(dir.path(), true, &path);
    let tools = hermes_host_tools(&runtime);
    let contract = email_send_contract();
    let scope = Scope::default();

    let business_send = serde_json::json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": draft_digest });
    let retry_send = serde_json::json!({
        "account": ACCOUNT,
        "draft_id": "draft-1",
        "draft_digest": draft_digest,
        "approvalId": "approval:r3:fixture"
    });
    let business_propose = serde_json::json!({
        "account": ACCOUNT,
        "type": "create",
        "title": "Standup",
        "start": "2026-09-26T10:00:00Z",
        "end": "2026-09-26T11:00:00Z",
    });

    // Healthy: phase one (no approvalId anywhere) admits, and the phase
    // two shape re-admits through the identical gate.
    for (name, arguments) in [
        (
            "email_search",
            serde_json::json!({ "account": ACCOUNT, "text": "query" }),
        ),
        (
            "email_read",
            serde_json::json!({ "account": ACCOUNT, "email_id": "m-1" }),
        ),
        (
            "email_draft",
            serde_json::json!({ "account": ACCOUNT, "subject": "s", "body_text": "b" }),
        ),
        ("email_send", business_send.clone()),
        ("email_send", retry_send.clone()),
        (
            "calendar_read",
            serde_json::json!({ "account": ACCOUNT, "start": "2026-09-26T10:00:00Z", "end": "2026-09-26T11:00:00Z" }),
        ),
        ("calendar_propose", business_propose.clone()),
    ] {
        tool(&tools, name)
            .preflight(&contract, &scope, &arguments)
            .unwrap_or_else(|error| panic!("{name} must admit healthy arguments: {error}"));
    }

    // The credential disappears: every gate refuses with the typed
    // credential-unavailable sentence — before a dispatch could journal,
    // mint an approval, or consume one.
    std::fs::remove_file(&path).unwrap();
    for (name, arguments) in [
        (
            "email_search",
            serde_json::json!({ "account": ACCOUNT, "text": "query" }),
        ),
        (
            "email_read",
            serde_json::json!({ "account": ACCOUNT, "email_id": "m-1" }),
        ),
        (
            "email_draft",
            serde_json::json!({ "account": ACCOUNT, "subject": "s", "body_text": "b" }),
        ),
        ("email_send", business_send),
        ("email_send", retry_send),
        (
            "calendar_read",
            serde_json::json!({ "account": ACCOUNT, "start": "2026-09-26T10:00:00Z", "end": "2026-09-26T11:00:00Z" }),
        ),
        ("calendar_propose", business_propose),
    ] {
        let error = tool(&tools, name)
            .preflight(&contract, &scope, &arguments)
            .expect_err("{name} must refuse a vanished credential before dispatch");
        match &error {
            HostToolError::Unavailable { tool, reason } => {
                assert_eq!(*tool, name);
                assert!(
                    reason.contains("credential"),
                    "{name} refusal must name the credential prerequisite, got {reason}"
                );
            }
            other => panic!("{name} must refuse with typed unavailability, got {other:?}"),
        }
    }

    // The observation was effect-free: the gate wrote nothing and the
    // only filesystem change is the removal above.
    assert!(!path.exists());
}

/// The R3 first-call phase contract, end to end at the surfaces that
/// admit arguments: the tool definitions and the canonical schemas must
/// accept the business request BEFORE the approvalId exists, keep the
/// selector optional (never required, never dummy-synthesized), and the
/// canonical schema must still forbid every other unknown key — no
/// authority is widened beyond the declared retry selector.
#[test]
fn r3_surfaces_admit_the_business_request_before_the_approval_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sinmara-email.secret");
    std::fs::write(&path, SECRET_VALUE).unwrap();
    let (runtime, draft_digest) = runtime_with_email(dir.path(), true, &path);
    let tools = hermes_host_tools(&runtime);

    // Model-surface definitions: the retry selector is declared and
    // optional on both gated tools.
    for name in ["email_send", "calendar_propose"] {
        let parameters = &tool(&tools, name).definition().parameters;
        let selector = parameters
            .get("properties")
            .and_then(|properties| properties.get("approvalId"))
            .unwrap_or_else(|| panic!("{name} must declare the approvalId selector"));
        assert_eq!(
            selector.get("type").and_then(serde_json::Value::as_str),
            Some("string"),
            "{name} approvalId must be a string selector"
        );
        let required = parameters
            .get("required")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            !required
                .iter()
                .any(|entry| entry == &serde_json::json!("approvalId")),
            "{name} must not require approvalId on the first dispatch"
        );
    }

    // Canonical schemas from the repository filesystem — the same files
    // the production schema catalog serves.
    let schemas_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/capability");
    let load = |name: &str| {
        let raw = std::fs::read_to_string(schemas_root.join(name)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        ToolSchema::from_value(value).unwrap()
    };
    let window = serde_json::json!({
        "start": "2026-09-26T10:00:00Z",
        "end": "2026-09-26T11:00:00Z",
    });
    let cases: &[(&str, serde_json::Value, serde_json::Value)] = &[
        (
            "email.send.input.json",
            serde_json::json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": draft_digest }),
            serde_json::json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": draft_digest, "approvalId": "approval:r3:fixture" }),
        ),
        (
            "calendar.propose.input.json",
            serde_json::json!({ "account": ACCOUNT, "type": "create", "title": "Standup", "start": window["start"].clone(), "end": window["end"].clone() }),
            serde_json::json!({ "account": ACCOUNT, "type": "create", "title": "Standup", "start": window["start"].clone(), "end": window["end"].clone(), "approvalId": "approval:r3:fixture" }),
        ),
    ];
    for (file, business, retry) in cases {
        let schema = load(file);
        // Phase one admits the business request with no approval identity.
        odin_kernel::validate_input_arguments(&schema, business)
            .unwrap_or_else(|error| panic!("{file} must admit the first call: {error}"));
        // Phase two admits the real selector naming the minted request.
        odin_kernel::validate_input_arguments(&schema, retry)
            .unwrap_or_else(|error| panic!("{file} must admit the approved retry: {error}"));
        // No authority widening: a rogue key is still refused outright.
        let mut rogue = business.clone();
        rogue["rogue"] = serde_json::json!(true);
        assert!(
            odin_kernel::validate_input_arguments(&schema, &rogue).is_err(),
            "{file} must still forbid undeclared keys"
        );
        // The selector is declared but never required.
        let required = schema
            .canonical_json()
            .get("required")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            !required
                .iter()
                .any(|entry| entry == &serde_json::json!("approvalId")),
            "{file} must not require approvalId"
        );
    }
}
