//! Settlement hardening: lease account binding is enforced at every exchange.

use crate::fixtures::{
    calendar_transport_over, email_transport_over, jmap_response, now, ScriptedJmap, ACCOUNT,
    SECRET_VALUE,
};
use odin_domain::CapabilityId;
use odin_hermes::account::CredentialLeases as _;
use odin_hermes::account::{AccountSecretRef, FileCredentialLeases, TransportFault};
use odin_hermes::calendar::CalendarTransport as _;
use odin_hermes::calendar::CalendarWindow;
use odin_hermes::email::EmailSearchQuery;
use odin_hermes::email::EmailTransport as _;
use std::collections::BTreeMap;

#[test]
fn lease_account_binding_is_enforced_at_every_exchange() {
    // A lease bound to one account never serves another account's query:
    // the transport refuses before any request is built or sent.
    let dir = tempfile::tempdir().unwrap();
    let mut accounts = BTreeMap::new();
    for (name, file) in [("personal", "a.secret"), ("other", "b.secret")] {
        let path = dir.path().join(file);
        std::fs::write(&path, SECRET_VALUE).unwrap();
        accounts.insert(
            name.to_owned(),
            AccountSecretRef::new(
                odin_domain::huginn::OpaqueCredentialHandle::new(format!("cred:{name}")).unwrap(),
                path,
            )
            .unwrap(),
        );
    }
    let leases = FileCredentialLeases::new(accounts);

    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "subscription".to_owned(),
        limit: 5,
    };
    let exchange = ScriptedJmap::with_response(jmap_response(&[]));
    let (transport, shared) = email_transport_over(exchange);
    let other_lease = leases
        .issue(&CapabilityId::new("email.search").unwrap(), "other", now())
        .expect("the other account's lease");
    assert!(matches!(
        transport.search(&other_lease, &query, now()),
        Err(TransportFault::Refused(_))
    ));

    let calendar_exchange = ScriptedJmap::with_response(jmap_response(&[]));
    let (calendar, calendar_shared) = calendar_transport_over(calendar_exchange);
    let calendar_lease = leases
        .issue(&CapabilityId::new("calendar.read").unwrap(), "other", now())
        .expect("the other account's calendar lease");
    let window = CalendarWindow {
        account: ACCOUNT.to_owned(),
        start: "2026-08-01T00:00:00Z".to_owned(),
        end: "2026-08-31T23:59:59Z".to_owned(),
    };
    assert!(matches!(
        calendar.read_window(&calendar_lease, &window, now()),
        Err(TransportFault::Refused(_))
    ));

    // Zero exchanges: the refusal happened before any wire request.
    assert!(shared.requests.lock().is_empty());
    assert!(calendar_shared.requests.lock().is_empty());
    drop(dir);
}
