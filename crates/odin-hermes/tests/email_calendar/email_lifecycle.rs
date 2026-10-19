//! Fixture-driven email reads, typed unavailability, and idempotent draft saves.

use crate::fixtures::{
    email_world, fixture_draft, fixtures, identity, now, secret_dir, ACCOUNT, EMAIL_CANARY,
};
use odin_hermes::account::{
    AccountSecretRef, AccountUnavailable, EffectStatus, FileCredentialLeases, LifeError,
    TransportFault,
};
use odin_hermes::email::EmailSearchQuery;
use std::collections::BTreeMap;

#[test]
fn fixture_search_and_read_serve_fixture_data() {
    let fixture = fixtures();
    let (dir, leases) = secret_dir();
    let (adapter, transport, _ledger) = email_world(&fixture, leases);

    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "subscription".to_owned(),
        limit: 20,
    };
    let summaries = adapter.search(&query, now()).unwrap();
    let expected: Vec<String> = fixture
        .email
        .messages
        .iter()
        .filter(|message| {
            message.body.contains("subscription") || message.subject.contains("subscription")
        })
        .map(|message| message.id.clone())
        .collect();
    assert_eq!(
        summaries.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        expected
    );

    let target = &fixture.email.messages[0];
    let message = adapter.read(ACCOUNT, &target.id, now()).unwrap().unwrap();
    assert_eq!(message.body_text.as_deref(), Some(target.body.as_str()));
    assert!(adapter
        .read(ACCOUNT, "absent-email", now())
        .unwrap()
        .is_none());

    // Every read-path lease bound the read capability to this account.
    for (capability, account) in transport.calls() {
        assert_eq!(account, ACCOUNT);
        assert!(
            capability == "email.search" || capability == "email.read",
            "unexpected capability {capability}"
        );
    }
    drop(dir);
}
#[test]
fn unavailable_accounts_and_credentials_are_typed() {
    let fixture = fixtures();
    let (dir, leases) = secret_dir();
    let (adapter, _transport, _ledger) = email_world(&fixture, leases);

    let ghost = EmailSearchQuery {
        account: "ghost".to_owned(),
        text: "subscription".to_owned(),
        limit: 5,
    };
    assert_eq!(
        adapter.search(&ghost, now()),
        Err(LifeError::Unavailable(AccountUnavailable::Account))
    );

    let missing = missing_credential_leases(&dir);
    let (adapter, _transport, _ledger) = email_world(&fixture, missing);
    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "subscription".to_owned(),
        limit: 5,
    };
    assert_eq!(
        adapter.search(&query, now()),
        Err(LifeError::Unavailable(AccountUnavailable::Credentials))
    );
    let target_id = fixture.email.messages[0].id.clone();

    let (dir, leases) = secret_dir();
    let (adapter, transport, _ledger) = email_world(&fixture, leases);
    *transport.read_fault.lock() = Some(TransportFault::Unavailable(AccountUnavailable::Service));
    assert_eq!(
        adapter.read(ACCOUNT, &target_id, now()),
        Err(LifeError::Unavailable(AccountUnavailable::Service))
    );
    *transport.read_fault.lock() = Some(TransportFault::Timeout);
    assert_eq!(
        adapter.read(ACCOUNT, &target_id, now()),
        Err(LifeError::Timeout)
    );
    *transport.read_fault.lock() = Some(TransportFault::Protocol("shape"));
    assert!(matches!(
        adapter.read(ACCOUNT, &target_id, now()),
        Err(LifeError::Protocol(_))
    ));
    drop(dir);
}
#[test]
fn draft_save_replays_exactly_once() {
    let fixture = fixtures();
    let (dir, leases) = secret_dir();
    let (adapter, transport, _ledger) = email_world(&fixture, leases);

    let body = format!("Invoice attached. {}", EMAIL_CANARY);
    let draft = fixture_draft(&fixture, "Quarterly invoice", &body);
    let key = identity("draft-once");

    let first = adapter.save_draft(&key, &draft, now()).unwrap();
    assert_eq!(first.status, EffectStatus::Completed);
    assert_eq!(first.result["draftId"], "draft-1");
    assert!(!first.replayed);

    let replay = adapter.save_draft(&key, &draft, now()).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.result["draftId"], "draft-1");
    assert_eq!(first.result, replay.result);
    assert_eq!(first.result.as_object().unwrap().len(), 2);
    assert!(first.result["draftDigest"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(!serde_json::to_string(&replay)
        .unwrap()
        .contains(EMAIL_CANARY));
    assert!(replay.result.get("draftReceipt").is_none());

    // Same key, different content: the digest check refuses it.
    let mutated = fixture_draft(&fixture, "Different subject", &body);
    assert!(matches!(
        adapter.save_draft(&key, &mutated, now()),
        Err(LifeError::InvalidInput(_))
    ));

    assert_eq!(transport.calls().len(), 1);
    drop(dir);
}
/// A lease source for an account whose credential file is missing.
fn missing_credential_leases(dir: &tempfile::TempDir) -> FileCredentialLeases {
    let mut accounts = BTreeMap::new();
    accounts.insert(
        ACCOUNT.to_owned(),
        AccountSecretRef::new(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:sinmara-email").unwrap(),
            dir.path().join("absent.secret"),
        )
        .unwrap(),
    );
    FileCredentialLeases::new(accounts)
}
