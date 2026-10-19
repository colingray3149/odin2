//! JMAP request construction and response parsing for email and calendar.

use crate::fixtures::{
    calendar_transport_over, email_transport_over, fixture_event_draft, fixtures, jmap_response,
    now, secret_dir, ScriptedJmap, ACCOUNT,
};
use odin_domain::CapabilityId;
use odin_hermes::account::CredentialLeases as _;
use odin_hermes::account::{
    AccountUnavailable, FileCredentialLeases, ScopedCredentialLease, TransportFault,
    LEASE_TTL_SECONDS,
};
use odin_hermes::calendar::CalendarWindow;
use odin_hermes::calendar::{CalendarMutation, CalendarProposal, CalendarTransport as _};
use odin_hermes::email::EmailTransport as _;
use odin_hermes::email::{EmailDraft, EmailManagement, EmailManagementAction, EmailSearchQuery};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[test]
fn jmap_email_transport_builds_and_parses_strictly() {
    let fixture = fixtures();
    let message = &fixture.email.messages[0];
    let response = jmap_response(&[
        (
            "Email/query",
            serde_json::json!({ "ids": [message.id], "notFound": [] }),
            "q",
        ),
        (
            "Email/get",
            serde_json::json!({ "list": [{
                "id": message.id,
                "subject": message.subject,
                "receivedAt": message.received_at,
                "from": [{ "name": null, "email": message.from }],
                "preview": "preview text",
                "textBody": [{ "partId": "p1", "type": "text/plain" }],
                "bodyValues": { "p1": { "value": message.body } },
            }], "notFound": [] }),
            "g",
        ),
    ]);
    let exchange = ScriptedJmap::with_response(response);
    let (transport, shared) = email_transport_over(exchange);
    let (_dir, leases) = secret_dir();
    let lease = issue_lease(&leases, "email.search");
    let read_lease = issue_lease(&leases, "email.read");
    let query = EmailSearchQuery {
        account: ACCOUNT.to_owned(),
        text: "subscription".to_owned(),
        limit: 10,
    };
    let summaries = transport.search(&lease, &query, now()).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, message.id);
    assert_eq!(
        summaries[0].subject.as_deref(),
        Some(message.subject.as_str())
    );

    let request = shared.last_request();
    assert!(request
        .using
        .iter()
        .any(|urn| urn == "urn:ietf:params:jmap:mail"));
    assert_eq!(request.method_calls[0].name, "Email/query");
    assert_eq!(request.method_calls[0].arguments["accountId"], "acct-1");
    assert_eq!(
        request.method_calls[0].arguments["filter"]["text"],
        "subscription"
    );
    assert_eq!(request.method_calls[0].arguments["limit"], 10);
    assert_eq!(request.method_calls[1].name, "Email/get");
    assert_eq!(request.method_calls[1].arguments["#ids"]["resultOf"], "q");

    let message_read = transport
        .read(&read_lease, &message.id, now())
        .unwrap()
        .unwrap();
    assert_eq!(
        message_read.body_text.as_deref(),
        Some(message.body.as_str())
    );
    let request = shared.last_request();
    assert_eq!(
        request.method_calls[0].arguments["fetchTextBodyValues"],
        true
    );

    // An absent message is the honest empty answer: the scripted reply
    // is request-blind, so the absent-id scenario serves its own
    // Email/get response — an empty list (the id lands in notFound).
    let absent_exchange = ScriptedJmap::with_response(jmap_response(&[(
        "Email/get",
        serde_json::json!({ "list": [], "notFound": ["absent-email"] }),
        "g",
    )]));
    let (absent_transport, _absent_shared) = email_transport_over(absent_exchange);
    assert!(absent_transport
        .read(&read_lease, "absent-email", now())
        .unwrap()
        .is_none());

    // A method-level error and an off-bounds field are typed faults.
    let error_exchange = ScriptedJmap::with_response(jmap_response(&[(
        "error",
        serde_json::json!({ "type": "unknownMethod" }),
        "q",
    )]));
    let (error_transport, _shared) = email_transport_over(error_exchange);
    assert!(matches!(
        error_transport.search(&lease, &query, now()),
        Err(TransportFault::Protocol(_))
    ));

    // RFC 8620 §3.6.2: accountNotFound is a typed account unavailability.
    let unknown_account = ScriptedJmap::with_response(jmap_response(&[(
        "error",
        serde_json::json!({ "type": "accountNotFound" }),
        "q",
    )]));
    let (unknown_transport, _shared) = email_transport_over(unknown_account);
    assert_eq!(
        unknown_transport.search(&lease, &query, now()),
        Err(TransportFault::Unavailable(AccountUnavailable::Account))
    );

    let oversized = jmap_response(&[
        (
            "Email/query",
            serde_json::json!({ "ids": [message.id] }),
            "q",
        ),
        (
            "Email/get",
            serde_json::json!({ "list": [{
                "id": message.id,
                "subject": "x".repeat(600),
                "from": [{ "email": message.from }],
            }], "notFound": [] }),
            "g",
        ),
    ]);
    let (oversize_transport, _shared) =
        email_transport_over(ScriptedJmap::with_response(oversized));
    assert!(matches!(
        oversize_transport.search(&lease, &query, now()),
        Err(TransportFault::Protocol(_))
    ));

    let fault_exchange = ScriptedJmap::with_fault(TransportFault::Timeout);
    let (fault_transport, _shared) = email_transport_over(fault_exchange);
    assert_eq!(
        fault_transport.search(&lease, &query, now()),
        Err(TransportFault::Timeout)
    );

    // Use-time lease enforcement: a lease that does not bind this
    // operation (or has expired) is refused with zero exchanges.
    let refusal_exchange = ScriptedJmap::with_response(jmap_response(&[]));
    let refusal = Arc::new(refusal_exchange);
    let refused_transport = {
        let exchange = refusal.clone();
        odin_hermes::email::JmapEmailTransport::new(odin_hermes::email::JmapMailConfig {
            account_id: "acct-1".to_owned(),
            identity_id: "ident-1".to_owned(),
            from_address: "sinmara@example.test".to_owned(),
            drafts_mailbox_id: "drafts-1".to_owned(),
            archive_mailbox_id: "archive-1".to_owned(),
            trash_mailbox_id: "trash-1".to_owned(),
            exchange,
        })
        .unwrap()
    };
    let (_refused_dir, refused_leases) = secret_dir();
    let wrong_capability = issue_lease(&refused_leases, "email.search");
    let draft = EmailDraft {
        account: ACCOUNT.to_owned(),
        to: vec![message.from.clone()],
        subject: "Wrong lease".to_owned(),
        body_text: "never exchanged".to_owned(),
    };
    assert!(matches!(
        refused_transport.save_draft(&wrong_capability, &draft, now()),
        Err(TransportFault::Refused(_))
    ));
    let search_cap = CapabilityId::new("email.search").unwrap();
    let expired = refused_leases
        .issue(
            &search_cap,
            ACCOUNT,
            now() - Duration::seconds(LEASE_TTL_SECONDS),
        )
        .unwrap();
    assert!(matches!(
        refused_transport.search(&expired, &query, now()),
        Err(TransportFault::Refused(_))
    ));
    assert!(refusal.requests.lock().is_empty());
}
#[test]
fn jmap_email_draft_and_send_build_expected_requests() {
    let fixture = fixtures();
    let message = &fixture.email.messages[0];
    let draft = EmailDraft {
        account: ACCOUNT.to_owned(),
        to: vec![message.from.clone()],
        subject: message.subject.clone(),
        body_text: message.body.clone(),
    };

    let create_response = jmap_response(&[(
        "Email/set",
        serde_json::json!({ "oldState": "s1", "newState": "s2", "created": { "draft": { "id": "draft-9" } } }),
        "s",
    )]);
    let (transport, shared) = email_transport_over(ScriptedJmap::with_response(create_response));
    let (_dir, leases) = secret_dir();
    let draft_lease = issue_lease(&leases, "email.draft");
    let send_lease = issue_lease(&leases, "email.send");
    let draft_id = transport.save_draft(&draft_lease, &draft, now()).unwrap();
    assert_eq!(draft_id.draft_id, "draft-9");
    let request = shared.last_request();
    let created = &request.method_calls[0].arguments["create"]["draft"];
    assert_eq!(created["keywords"]["$draft"], true);
    assert!(created["mailboxIds"]["drafts-1"].as_bool().unwrap());
    assert_eq!(created["from"][0]["email"], "sinmara@example.test");
    assert_eq!(created["to"][0]["email"], message.from.as_str());
    assert_eq!(created["textBody"][0]["type"], "text/plain");

    let refused = jmap_response(&[(
        "Email/set",
        serde_json::json!({ "notCreated": { "draft": { "type": "tooLarge" } } }),
        "s",
    )]);
    let (refused_transport, _shared) = email_transport_over(ScriptedJmap::with_response(refused));
    assert!(matches!(
        refused_transport.save_draft(&draft_lease, &draft, now()),
        Err(TransportFault::Protocol(_))
    ));

    let send_response = jmap_response(&[(
        "EmailSubmission/set",
        serde_json::json!({ "created": { "send": { "id": "sub-9" } } }),
        "m",
    )]);
    let (send_transport, shared) = email_transport_over(ScriptedJmap::with_response(send_response));
    let sent_id = send_transport
        .send_draft(&send_lease, &draft_id, now())
        .unwrap();
    assert_eq!(sent_id, "sub-9");
    let request = shared.last_request();
    assert!(request
        .using
        .iter()
        .any(|urn| urn == "urn:ietf:params:jmap:submission"));
    assert_eq!(request.method_calls[0].name, "EmailSubmission/set");
    assert_eq!(
        request.method_calls[0].arguments["create"]["send"]["identityId"],
        "ident-1"
    );
    assert_eq!(
        request.method_calls[0].arguments["create"]["send"]["emailId"],
        "draft-9"
    );
    let wrong_account = odin_hermes::email::EmailDraftReceipt {
        draft_id: "draft-9".into(),
        binding: odin_hermes::email::DraftContentBinding::Jmap {
            account_id: "different-remote-account".into(),
        },
    };
    assert!(matches!(
        send_transport.send_draft(&send_lease, &wrong_account, now()),
        Err(TransportFault::Refused(_))
    ));
    assert_eq!(shared.requests.lock().len(), 1);
}
#[test]
fn jmap_calendar_transport_builds_and_parses_strictly() {
    let fixture = fixtures();
    let event = &fixture.calendar.events[0];
    let start = format!(
        "{}T{}:00Z",
        event.date,
        event.time.clone().unwrap_or_else(|| "09:00".to_owned())
    );
    let response = jmap_response(&[
        (
            "CalendarEvent/query",
            serde_json::json!({ "ids": [event.id] }),
            "q",
        ),
        (
            "CalendarEvent/get",
            serde_json::json!({ "list": [{
                "id": event.id,
                "title": event.title,
                "utcStart": start,
                "utcEnd": (OffsetDateTime::parse(&start, &Rfc3339).unwrap()
                    + Duration::minutes(30))
                    .format(&Rfc3339).unwrap(),
                "description": "fixture",
            }], "notFound": [] }),
            "g",
        ),
    ]);
    let (transport, shared) = calendar_transport_over(ScriptedJmap::with_response(response));
    let (_dir, leases) = secret_dir();
    let lease = issue_lease(&leases, "calendar.read");

    let window = CalendarWindow {
        account: ACCOUNT.to_owned(),
        start: "2026-08-01T00:00:00Z".to_owned(),
        end: "2026-08-31T23:59:59Z".to_owned(),
    };
    let events = transport.read_window(&lease, &window, now()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, event.id);
    let start_at = OffsetDateTime::parse(&start, &Rfc3339).unwrap();
    assert_eq!(
        events[0].end,
        (start_at + Duration::minutes(30)).format(&Rfc3339).unwrap()
    );
    let request = shared.last_request();
    // RFC 8620/JSCalendar: after/before are local date-times evaluated
    // in the query timeZone; the narrow adapter pins Etc/UTC.
    assert_eq!(
        request.method_calls[0].arguments["filter"]["after"],
        "2026-08-01T00:00:00"
    );
    assert_eq!(
        request.method_calls[0].arguments["filter"]["before"],
        "2026-08-31T23:59:59"
    );
    assert_eq!(request.method_calls[0].arguments["timeZone"], "Etc/UTC");
    assert_eq!(request.method_calls[0].arguments["expandRecurrences"], true);

    let malformed = jmap_response(&[
        (
            "CalendarEvent/query",
            serde_json::json!({ "ids": [event.id] }),
            "q",
        ),
        (
            "CalendarEvent/get",
            serde_json::json!({ "list": [{
                "id": event.id,
                "title": event.title,
                "utcStart": start,
            }], "notFound": [] }),
            "g",
        ),
    ]);
    let (malformed_transport, _shared) =
        calendar_transport_over(ScriptedJmap::with_response(malformed));
    assert!(matches!(
        malformed_transport.read_window(&lease, &window, now()),
        Err(TransportFault::Protocol(_))
    ));

    let draft = fixture_event_draft(&fixture, 0);
    let proposal = CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::Create(draft.clone()),
    };
    let create_response = jmap_response(&[(
        "CalendarEvent/set",
        serde_json::json!({ "created": { "e": { "id": "event-9" } } }),
        "b",
    )]);
    let (apply_transport, shared) =
        calendar_transport_over(ScriptedJmap::with_response(create_response));
    let propose_lease = issue_lease(&leases, "calendar.propose");
    let receipt = apply_transport
        .apply(&propose_lease, &proposal, now())
        .unwrap();
    assert_eq!(receipt.event_ids, ["event-9"]);
    let request = shared.last_request();
    let created = &request.method_calls[0].arguments["create"]["e"];
    assert!(created["calendarIds"]["cal-1"].as_bool().unwrap());
    assert_eq!(created["title"], draft.title);
    assert_eq!(created["utcStart"], draft.start);
    assert_eq!(created["utcEnd"], draft.end);
    assert_eq!(created["locations"]["loc"]["name"], "Fixture Room");
}

/// Batch ids retain draft order; cancellation patches status and management uses JSON Pointer keywords.
#[test]
fn jmap_mutations_and_manage_build_expected_requests() {
    let fixture = fixtures();
    let (_dir, leases) = secret_dir();
    let propose_lease = issue_lease(&leases, "calendar.propose");

    let batch = CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::BatchCreate {
            drafts: vec![
                fixture_event_draft(&fixture, 0),
                fixture_event_draft(&fixture, 1),
            ],
        },
    };
    let (batch_transport, shared) =
        calendar_transport_over(ScriptedJmap::with_response(jmap_response(&[(
            "CalendarEvent/set",
            serde_json::json!({
                "created": { "d0": { "id": "e-2" }, "d1": { "id": "e-1" } }
            }),
            "b",
        )])));
    let receipt = batch_transport
        .apply(&propose_lease, &batch, now())
        .unwrap();
    assert_eq!(receipt.event_ids, ["e-2", "e-1"]);
    let request = shared.last_request();
    assert!(request.method_calls[0].arguments["create"]["d0"].is_object());
    assert!(request.method_calls[0].arguments["create"]["d1"].is_object());

    // A rejected member prevents completion, but acknowledged members
    // remain known partial effects.
    let (rejected_transport, _shared) =
        calendar_transport_over(ScriptedJmap::with_response(jmap_response(&[(
            "CalendarEvent/set",
            serde_json::json!({
                "created": { "d0": { "id": "e-2" } },
                "notCreated": { "d1": { "type": "tooMany" } },
            }),
            "b",
        )])));
    let partial = rejected_transport
        .apply(&propose_lease, &batch, now())
        .expect_err("the batch did not complete");
    assert_eq!(partial.applied, ["e-2"]);

    let cancel = CalendarProposal {
        account: ACCOUNT.to_owned(),
        mutation: CalendarMutation::Cancel {
            event_id: fixture.calendar.events[0].id.clone(),
        },
    };
    let (cancel_transport, shared) =
        calendar_transport_over(ScriptedJmap::with_response(jmap_response(&[(
            "CalendarEvent/set",
            serde_json::json!({ "updated": { "cal-001": null } }),
            "b",
        )])));
    let receipt = cancel_transport
        .apply(&propose_lease, &cancel, now())
        .unwrap();
    assert_eq!(receipt.event_ids, [fixture.calendar.events[0].id.clone()]);
    let request = shared.last_request();
    assert_eq!(
        request.method_calls[0].arguments["update"]["cal-001"]["status"],
        "cancelled"
    );

    let management = EmailManagement {
        account: ACCOUNT.to_owned(),
        actions: vec![
            EmailManagementAction::Label {
                email_id: "email-001".to_owned(),
                add_labels: vec!["$flagged".to_owned()],
                remove_labels: vec!["$seen".to_owned()],
            },
            EmailManagementAction::Archive {
                email_id: "email-002".to_owned(),
            },
            EmailManagementAction::Trash {
                email_id: "email-003".to_owned(),
            },
        ],
    };
    let (manage_transport, shared) =
        email_transport_over(ScriptedJmap::with_response(jmap_response(&[(
            "Email/set",
            serde_json::json!({
                "updated": {
                    "email-001": null,
                    "email-002": null,
                    "email-003": null,
                }
            }),
            "o",
        )])));
    let manage_lease = issue_lease(&leases, "email.manage");
    let receipt = manage_transport
        .manage(&manage_lease, &management, now())
        .unwrap();
    assert_eq!(receipt.email_ids, ["email-001", "email-002", "email-003"]);
    let request = shared.last_request();
    let update = &request.method_calls[0].arguments["update"];
    assert_eq!(
        update["email-001"]["keywords/$flagged"],
        serde_json::json!(true)
    );
    assert_eq!(
        update["email-001"]["keywords/$seen"],
        serde_json::json!(null)
    );
    assert_eq!(
        update["email-002"]["mailboxIds"]["archive-1"],
        serde_json::json!(true)
    );
    assert_eq!(
        update["email-003"]["mailboxIds"]["trash-1"],
        serde_json::json!(true)
    );

    // A per-id rejection is a typed fault — never a partial success.
    let (partial_transport, _shared) =
        email_transport_over(ScriptedJmap::with_response(jmap_response(&[(
            "Email/set",
            serde_json::json!({
                "updated": { "email-001": null, "email-002": null },
                "notUpdated": { "email-003": { "type": "notFound" } },
            }),
            "o",
        )])));
    let partial = partial_transport
        .manage(&manage_lease, &management, now())
        .expect_err("the management batch did not complete");
    assert_eq!(partial.applied, ["email-001", "email-002"]);
}
/// Issues a real lease through the production lease source — the only
/// way tests obtain one, exactly like the runtime does.
fn issue_lease(leases: &FileCredentialLeases, capability: &'static str) -> ScopedCredentialLease {
    leases
        .issue(&CapabilityId::new(capability).unwrap(), ACCOUNT, now())
        .expect("fixture lease")
}
