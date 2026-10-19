//! Guarded effects: issuance is separate from resolution, and input bounds precede any dispatch.

use crate::fixtures::{
    calendar_transport_over, calendar_world, email_world, fixture_draft, fixture_event_draft,
    fixture_proposal, fixtures, identity, jmap_response, now, secret_dir, ScriptedJmap, ACCOUNT,
    EMAIL_CANARY, SECRET_VALUE,
};
use odin_domain::CapabilityId;
use odin_hermes::account::CredentialLeases as _;
use odin_hermes::account::{
    AccountUnavailable, BatchFault, LeaseRejection, LifeError, TransportFault, LEASE_TTL_SECONDS,
};
use odin_hermes::calendar::CalendarTransport as _;
use odin_hermes::calendar::{CalendarMutation, CalendarProposal, CalendarWindow};
use odin_hermes::email::{EmailDraft, EmailSearchQuery};
use time::Duration;

#[test]
fn lease_issuance_is_separate_from_credential_resolution() {
    let fixture = fixtures();
    let (dir, leases) = secret_dir();
    let search_cap = CapabilityId::new("email.search").unwrap();
    let lease = leases.issue(&search_cap, ACCOUNT, now()).unwrap();
    let (adapter, transport, _ledger) = email_world(&fixture, leases);

    // A settled effect with every canary planted into adapter input.
    let planted = &fixture.finance.planted_identifiers;
    assert!(planted.len() >= 2, "finance canaries must exist");
    let body = format!(
        "Wire the invoice to {}. Refs: {} and {}.",
        EMAIL_CANARY, planted[0], planted[1]
    );
    let draft = fixture_draft(&fixture, "Canary draft", &body);
    let settled = adapter
        .save_draft(&identity("draft-r1"), &draft, now())
        .unwrap();

    // A canary-bearing query: the results must not echo the input.
    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: format!("invoice {EMAIL_CANARY}"),
        limit: 20,
    };
    let summaries = adapter
        .search(&query, now())
        .expect("canary-bearing search");

    // Every outgoing artifact, serialized:
    let mut artifacts: Vec<String> = vec![
        serde_json::to_string(&settled).unwrap(),
        serde_json::to_string(&summaries).unwrap(),
    ];
    // ...the leases the transport actually received (Debug is the only
    // surface a lease exposes beyond its accessors):
    for (capability, account) in transport.calls() {
        artifacts.push(format!("lease-scope {capability} {account}"));
    }
    // Issue a lease directly and serialize every surface it exposes.
    let lease_debug = format!("{lease:?}");
    artifacts.push(lease_debug.clone());
    artifacts.push(lease.account().to_owned());
    artifacts.push(lease.capability().as_str().to_owned());

    // Lease scoping is enforced at use time, not just issuance time.
    let send_cap = CapabilityId::new("email.send").unwrap();
    assert_eq!(
        lease.admits(&send_cap, ACCOUNT, now()),
        Err(LeaseRejection::ScopeMismatch)
    );
    assert_eq!(
        lease.admits(&search_cap, "other", now()),
        Err(LeaseRejection::ScopeMismatch)
    );
    assert_eq!(
        lease.admits(
            &search_cap,
            ACCOUNT,
            now() + Duration::seconds(LEASE_TTL_SECONDS)
        ),
        Err(LeaseRejection::Expired)
    );
    assert!(lease.admits(&search_cap, ACCOUNT, now()).is_ok());

    // The separate resolution stage: only the trusted backend holding
    // the secret path can resolve the value. The lease carries none of
    // it, and no adapter surface ever does.
    let secret_path = dir.path().join("sinmara-email.secret");
    let resolved = odin_hermes::jmap::resolve_bearer(&secret_path)
        .expect("the sops-rendered secret file resolves");
    // The resolved value stays sealed: Debug is the only surface and it
    // redacts, so the bearer value cannot leak through the resolution
    // stage either.
    let resolved_debug = format!("{resolved:?}");
    assert!(resolved_debug.contains("[REDACTED]"));
    assert!(!resolved_debug.contains(SECRET_VALUE));
    // A missing secret file is typed unavailable, never an empty token;
    // an empty secret is a typed protocol fault.
    assert!(matches!(
        odin_hermes::jmap::resolve_bearer(&dir.path().join("absent.secret")),
        Err(TransportFault::Unavailable(AccountUnavailable::Credentials))
    ));
    let empty = dir.path().join("empty.secret");
    std::fs::write(&empty, "   \n").unwrap();
    assert!(matches!(
        odin_hermes::jmap::resolve_bearer(&empty),
        Err(TransportFault::Protocol(_))
    ));

    let canaries = [
        EMAIL_CANARY,
        planted[0].as_str(),
        planted[1].as_str(),
        SECRET_VALUE,
        "cred:sinmara-email",
    ];
    for artifact in &artifacts {
        for canary in canaries {
            assert!(
                !artifact.contains(canary),
                "canary {canary:?} leaked into outgoing artifact: {artifact}"
            );
        }
    }
    assert!(lease_debug.contains("[REDACTED]"));
    drop(dir);
}
#[test]
fn input_bounds_are_enforced_before_any_dispatch() {
    let fixture = fixtures();
    let (dir, leases) = secret_dir();
    let (adapter, transport, _ledger) = email_world(&fixture, leases);
    let (_calendar_dir, calendar_leases) = secret_dir();
    let (calendar, calendar_transport, _calendar_ledger) =
        calendar_world(&fixture, calendar_leases);

    let long_text = "a".repeat(401);
    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: long_text,
        limit: 5,
    };
    assert!(matches!(
        adapter.search(&query, now()),
        Err(LifeError::InvalidInput(_))
    ));
    let zero = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "subscription".to_owned(),
        limit: 0,
    };
    assert!(matches!(
        adapter.search(&zero, now()),
        Err(LifeError::InvalidInput(_))
    ));

    let too_many = fixture_draft(&fixture, "Bulk", "body");
    let mut recipients = too_many.to.clone();
    for index in 0..11 {
        recipients.push(format!("r{index}@example.test"));
    }
    let bulk = EmailDraft {
        account: ACCOUNT.to_owned(),
        to: recipients,
        subject: "Bulk".to_owned(),
        body_text: "body".to_owned(),
    };
    assert!(matches!(
        adapter.save_draft(&identity("draft-bulk"), &bulk, now()),
        Err(LifeError::InvalidInput(_))
    ));

    let backwards = CalendarWindow {
        account: ACCOUNT.to_owned(),
        start: "2026-08-02T00:00:00Z".to_owned(),
        end: "2026-08-01T00:00:00Z".to_owned(),
    };
    assert!(matches!(
        calendar.read_window(&backwards, now()),
        Err(LifeError::InvalidInput(_))
    ));
    let year_long = CalendarWindow {
        account: ACCOUNT.to_owned(),
        start: "2026-08-01T00:00:00Z".to_owned(),
        end: "2027-09-01T00:00:00Z".to_owned(),
    };
    assert!(matches!(
        calendar.read_window(&year_long, now()),
        Err(LifeError::InvalidInput(_))
    ));

    // Proposal bounds: the provider transport refuses an out-of-bounds
    // proposal before any wire request exists.
    let (_propose_dir, propose_leases) = secret_dir();
    let propose_lease = propose_leases
        .issue(
            &CapabilityId::new("calendar.propose").unwrap(),
            ACCOUNT,
            now(),
        )
        .unwrap();
    let (provider, provider_shared) =
        calendar_transport_over(ScriptedJmap::with_response(jmap_response(&[])));
    let mut subsecond = fixture_proposal(&fixture, 0, "subsec");
    let CalendarMutation::Create(draft) = &mut subsecond.mutation else {
        panic!("the fixture proposal creates");
    };
    draft.end = "2026-08-21T09:00:00.5Z".to_owned();
    assert!(matches!(
        provider.apply(&propose_lease, &subsecond, now()),
        Err(BatchFault {
            fault: TransportFault::Protocol(_),
            ..
        })
    ));

    // A batch over the bounded size refuses the same way.
    let flood = CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::BatchCreate {
            drafts: (0..129).map(|_| fixture_event_draft(&fixture, 0)).collect(),
        },
    };
    assert!(matches!(
        provider.apply(&propose_lease, &flood, now()),
        Err(BatchFault {
            fault: TransportFault::Protocol(_),
            ..
        })
    ));

    assert!(transport.calls().is_empty());
    assert!(calendar_transport.calls.lock().is_empty());
    assert!(provider_shared.requests.lock().is_empty());
    drop(dir);
}
