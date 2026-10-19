//! Production plane actor and scoped approval reader tests.
//!
//! The scripted daemon is a controlled external boundary only: it sits
//! behind the actual memory transport, decodes and encodes the real framed
//! Huginn protocol with the shared codec, and mirrors the production
//! dispatcher's live semantics exactly — an accepted Subscribe REPLACES the
//! connection's whole live stream and replays every subscription after its
//! exact cursor; ANY nonempty Unsubscribe DROPS the whole stream and
//! answers Ack. Nothing in the actor is mocked.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn as live;
use odin_huginn::client::{
    memory_transport, ColinRemoteClient, DeviceCredential, MemoryCredentialStore, MemoryServerEnd,
    MemoryServerHub, TransportFrame as _,
};
use odin_huginn::protocol::{decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::{kernel_approvals_reader, spawn_plane, PlaneEvent, PlaneHandle, PlaneOrder};

const SESSION_A: &str = "00000000-0000-4000-8000-0000000000a1";
const SESSION_B: &str = "00000000-0000-4000-8000-0000000000b2";
const TS: time::OffsetDateTime = time::OffsetDateTime::UNIX_EPOCH;

fn session_a() -> live::LiveSessionId {
    live::LiveSessionId::parse(SESSION_A).expect("fixture session id")
}

fn session_b() -> live::LiveSessionId {
    live::LiveSessionId::parse(SESSION_B).expect("fixture session id")
}

type Push = Option<ServerFrame>;

struct DaemonState {
    received: Mutex<Vec<ClientFrame>>,
    journal: Mutex<BTreeMap<live::LiveSessionId, Vec<Value>>>,
    refuse_next_subscribe: AtomicBool,
    pushes: Mutex<Option<mpsc::Sender<Push>>>,
}

type Ctx = Arc<DaemonState>;

async fn push(ctx: &Ctx, item: Push) {
    let sender = ctx
        .pushes
        .lock()
        .clone()
        .expect("a live scripted connection");
    sender
        .send(item)
        .await
        .expect("the connection accepts pushes");
}

fn live_response(request_id: live::RequestId, result: live::LiveResponse) -> ServerFrame {
    ServerFrame::Live(live::LiveServerMessage::Response { request_id, result })
}

/// The dispatcher pushes its refusal as a protocol error message, never as
/// a response; the client surfaces it as a `LiveProtocol` error and the
/// previous stream stays untouched.
fn protocol_error() -> ServerFrame {
    ServerFrame::Live(live::LiveServerMessage::ProtocolError(
        live::LiveProtocolError::ResourceLimit {
            limit: "subscriptionsPerConnection".to_owned(),
        },
    ))
}

fn handler(ctx: &Ctx, frame: &ClientFrame) -> Option<Vec<ServerFrame>> {
    match frame {
        ClientFrame::Live(live::LiveClientRequest::Subscribe {
            request_id,
            subscriptions,
        }) => {
            // Mirror of `dispatch_live`: an empty set is refused, and every
            // accepted subscribe replaces the connection's whole live
            // stream, replaying each subscription after its exact cursor.
            if subscriptions.is_empty() || ctx.refuse_next_subscribe.swap(false, Ordering::SeqCst) {
                return Some(vec![protocol_error()]);
            }
            let journal = ctx.journal.lock();
            let mut frames = vec![live_response(*request_id, live::LiveResponse::Subscribed)];
            for subscription in subscriptions {
                let session = subscription.session_id;
                let head = live::EventSeq::new(journal.get(&session).map_or(0, Vec::len) as u64);
                frames.push(ServerFrame::Live(live::LiveServerMessage::ReplayBegin {
                    session_id: session,
                    requested_after: subscription.event_after,
                    head,
                }));
                if let Some(events) = journal.get(&session) {
                    for (index, body) in events.iter().enumerate() {
                        let sequence = (index + 1) as u64;
                        if sequence > subscription.event_after.get() {
                            frames.push(event_frame(&session, sequence, 1, body.clone()));
                        }
                    }
                }
                frames.push(ServerFrame::Live(live::LiveServerMessage::ReplayComplete {
                    session_id: session,
                    head,
                }));
            }
            Some(frames)
        }
        ClientFrame::Live(live::LiveClientRequest::Unsubscribe {
            request_id,
            session_ids,
        }) => {
            // Mirror of `dispatch_live`: ANY nonempty unsubscribe drops the
            // connection's whole live stream and answers Ack; an empty list
            // is refused.
            if session_ids.is_empty() {
                return Some(vec![protocol_error()]);
            }
            Some(vec![live_response(*request_id, live::LiveResponse::Ack)])
        }
        _ => None,
    }
}

async fn serve(ctx: Ctx, mut end: MemoryServerEnd, mut pushes: mpsc::Receiver<Push>) {
    let limits = CodecLimits::default();
    loop {
        tokio::select! {
            biased;
            push = pushes.recv() => match push {
                Some(Some(frame)) => {
                    let Ok(bytes) = encode_frame(&frame, &limits) else { break };
                    if end.send_frame(bytes).await.is_err() {
                        break;
                    }
                }
                Some(None) | None => {
                    let _ = end.close().await;
                    break;
                }
            },
            incoming = end.next_frame() => {
                let Ok(Some(bytes)) = incoming else { break };
                let Ok(decoded) = decode_frame::<ClientFrame>(&bytes, &limits) else { break };
                ctx.received.lock().push(decoded.value.clone());
                if let Some(frames) = handler(&ctx, &decoded.value) {
                    for frame in frames {
                        let Ok(bytes) = encode_frame(&frame, &limits) else { break };
                        if end.send_frame(bytes).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn daemon(mut hub: MemoryServerHub, ctx: Ctx) {
    while let Some(end) = hub.accept().await {
        let (sender, receiver) = mpsc::channel::<Push>(16);
        *ctx.pushes.lock() = Some(sender);
        tokio::spawn(serve(ctx.clone(), end, receiver));
    }
}

fn state_body(previous: &str, current: &str) -> Value {
    json!({
        "kind": "sessionStateChanged",
        "payload": { "previous": previous, "current": current, "reason": Value::Null }
    })
}

fn event_frame(
    session: &live::LiveSessionId,
    sequence: u64,
    epoch: u64,
    body: Value,
) -> ServerFrame {
    serde_json::from_value(json!({
        "channel": "live",
        "value": { "kind": "event", "value": {
            "schemaVersion": 1,
            "eventId": format!("event:s{sequence}"),
            "sessionId": session.to_string(),
            "epoch": epoch,
            "sequence": sequence,
            "occurredAt": TS,
            "body": body,
        }}
    }))
    .expect("event frame")
}

struct Rig {
    ctx: Ctx,
    plane: PlaneHandle,
    events: mpsc::Receiver<PlaneEvent>,
}

async fn make_rig(journal: Vec<(live::LiveSessionId, Vec<Value>)>) -> Rig {
    let (transport, hub) = memory_transport(64);
    let ctx = Arc::new(DaemonState {
        received: Mutex::new(Vec::new()),
        journal: Mutex::new(journal.into_iter().collect()),
        refuse_next_subscribe: AtomicBool::new(false),
        pushes: Mutex::new(None),
    });
    tokio::spawn(daemon(hub, ctx.clone()));
    let credential = DeviceCredential::new(vec![1_u8; 48]).expect("credential");
    let store = MemoryCredentialStore::new(credential);
    let client = Arc::new(ColinRemoteClient::with_limits(
        transport,
        store,
        CodecLimits::default(),
    ));
    let (plane, events) = spawn_plane(client);
    Rig { ctx, plane, events }
}

async fn order(plane: &PlaneHandle, order: PlaneOrder) {
    plane
        .orders()
        .send(order)
        .await
        .expect("the plane accepts orders");
}

async fn next_event(events: &mut mpsc::Receiver<PlaneEvent>) -> PlaneEvent {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("a plane event arrives in time")
        .expect("the plane actor stays alive")
}

/// Waits through any in-flight noise for the next event the predicate
/// accepts.
async fn expect_event(
    events: &mut mpsc::Receiver<PlaneEvent>,
    wanted: impl Fn(&PlaneEvent) -> bool,
) -> PlaneEvent {
    loop {
        let event = next_event(events).await;
        if wanted(&event) {
            return event;
        }
    }
}

async fn wait_for_frames(ctx: &Ctx, count: usize) -> Vec<ClientFrame> {
    for _ in 0..2_000 {
        let frames = ctx.received.lock().clone();
        if frames.len() >= count {
            return frames;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for {count} scripted frames");
}

/// The cursor-bound subscription set of the `index`-th recorded frame.
fn subscribe_set(frames: &[ClientFrame], index: usize) -> Vec<(live::LiveSessionId, u64)> {
    match &frames[index] {
        ClientFrame::Live(live::LiveClientRequest::Subscribe { subscriptions, .. }) => {
            subscriptions
                .iter()
                .map(|subscription| (subscription.session_id, subscription.event_after.get()))
                .collect()
        }
        other => panic!("frame {index} is not a subscribe: {other:?}"),
    }
}

#[tokio::test]
async fn detach_of_two_replaces_the_stream_with_the_remaining_set() {
    let mut rig = make_rig(vec![(
        session_a(),
        vec![
            state_body("starting", "idle"),
            state_body("idle", "running"),
        ],
    )])
    .await;

    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_a(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    // Reply + full replay of the two journaled events, in wire order.
    let mut replayed = Vec::new();
    for _ in 0..5 {
        replayed.push(next_event(&mut rig.events).await);
    }
    assert!(matches!(&replayed[0], PlaneEvent::Subscribed { session } if *session == session_a()));
    assert!(matches!(&replayed[1], PlaneEvent::ReplayBegin { session } if *session == session_a()));
    assert!(matches!(&replayed[2], PlaneEvent::Event(_)));
    assert!(matches!(&replayed[3], PlaneEvent::Event(_)));
    assert!(
        matches!(&replayed[4], PlaneEvent::ReplayComplete { session } if *session == session_a())
    );

    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_b(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_b()),
    )
    .await;

    // The second subscribe carried the WHOLE desired set, with A's cursor
    // advanced by the replay it just delivered — never a rewind.
    let frames = wait_for_frames(&rig.ctx, 2).await;
    assert_eq!(
        subscribe_set(&frames, 1),
        vec![(session_a(), 2), (session_b(), 0)]
    );

    // Detaching one of two sessions must replace the stream with the
    // remaining cursor-bound set: a bare unsubscribe would drop the whole
    // connection stream on the production dispatcher and strand B.
    order(
        &rig.plane,
        PlaneOrder::Unsubscribe {
            session: session_a(),
        },
    )
    .await;
    expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::Unsubscribed)
    })
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_b()),
    )
    .await;

    let frames = wait_for_frames(&rig.ctx, 3).await;
    assert_eq!(subscribe_set(&frames, 2), vec![(session_b(), 0)]);
    assert!(frames.iter().all(|frame| matches!(
        frame,
        ClientFrame::Live(live::LiveClientRequest::Subscribe { .. })
    )));

    // The remaining session keeps receiving events after the detach.
    push(
        &rig.ctx,
        Some(event_frame(
            &session_b(),
            1,
            1,
            state_body("idle", "running"),
        )),
    )
    .await;
    let event = expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::Event(_))
    })
    .await;
    let PlaneEvent::Event(event) = event else {
        panic!("expected an event");
    };
    assert_eq!(event.session_id, session_b());
    assert_eq!(event.sequence.get(), 1);
}

#[tokio::test]
async fn detach_of_the_last_session_unsubscribes_exactly() {
    let mut rig = make_rig(vec![]).await;

    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_a(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_a()),
    )
    .await;

    order(
        &rig.plane,
        PlaneOrder::Unsubscribe {
            session: session_a(),
        },
    )
    .await;
    expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::Unsubscribed)
    })
    .await;

    let frames = wait_for_frames(&rig.ctx, 2).await;
    let ClientFrame::Live(live::LiveClientRequest::Unsubscribe { session_ids, .. }) = &frames[1]
    else {
        panic!("the empty detach must send the plain unsubscribe");
    };
    assert_eq!(session_ids.len(), 1);
    assert_eq!(session_ids[0], session_a());
}

#[tokio::test]
async fn reconnect_resubscribes_every_session_at_its_exact_cursor() {
    let mut rig = make_rig(vec![(session_a(), vec![state_body("starting", "idle")])]).await;

    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_a(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    for _ in 0..4 {
        next_event(&mut rig.events).await;
    }
    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_b(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_b()),
    )
    .await;

    // The transport resets: the memory connection closes under the actor.
    push(&rig.ctx, None).await;
    expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::Disconnected)
    })
    .await;

    // The recovery order names only A, and carries A's stale applied
    // cursor: the actor must still re-subscribe B (never silently drop a
    // still-attached session) and must never rewind A below the cursor it
    // already delivered.
    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_a(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_a()),
    )
    .await;

    let frames = wait_for_frames(&rig.ctx, 3).await;
    assert_eq!(
        subscribe_set(&frames, 2),
        vec![(session_a(), 1), (session_b(), 0)]
    );
}

#[tokio::test]
async fn refused_subscribe_is_rolled_back_and_never_confirmed() {
    let mut rig = make_rig(vec![]).await;

    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_a(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_a()),
    )
    .await;

    rig.ctx.refuse_next_subscribe.store(true, Ordering::SeqCst);
    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_b(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::SubscribeFailed { session, .. } if *session == session_b())
    })
    .await;

    // The rollback is wire-observable: with B rolled back, detaching A
    // leaves nothing desired, so the plain unsubscribe goes out — not a
    // replacement subscribe that would claim the refused session.
    order(
        &rig.plane,
        PlaneOrder::Unsubscribe {
            session: session_a(),
        },
    )
    .await;
    expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::Unsubscribed)
    })
    .await;

    let frames = wait_for_frames(&rig.ctx, 3).await;
    let ClientFrame::Live(live::LiveClientRequest::Unsubscribe { session_ids, .. }) = &frames[2]
    else {
        panic!("the refused session must not be resubscribed");
    };
    assert_eq!(session_ids.len(), 1);
    assert_eq!(session_ids[0], session_a());
}

#[tokio::test]
async fn revocation_stays_fatal() {
    let mut rig = make_rig(vec![]).await;

    order(
        &rig.plane,
        PlaneOrder::Subscribe {
            session: session_a(),
            after: live::EventSeq::new(0),
        },
    )
    .await;
    expect_event(
        &mut rig.events,
        |event| matches!(event, PlaneEvent::Subscribed { session } if *session == session_a()),
    )
    .await;

    push(
        &rig.ctx,
        Some(ServerFrame::Live(live::LiveServerMessage::DeviceRevoked)),
    )
    .await;
    expect_event(&mut rig.events, |event| {
        matches!(event, PlaneEvent::Failed(_))
    })
    .await;
}

fn run_approval(
    approval_id: &'static str,
    session: live::LiveSessionId,
) -> odin_ledger::approval::NewApproval {
    let now = time::OffsetDateTime::now_utc();
    odin_ledger::approval::NewApproval {
        approval_id: odin_domain::ApprovalId::new(approval_id).expect("approval id"),
        issuer: "seat:atlas".to_owned(),
        scope: odin_ledger::approval::ApprovalScope {
            target_kind: "run".to_owned(),
            target_id: format!("run:live:{session}"),
            capability_id: odin_domain::CapabilityId::new("kernel.act").expect("capability id"),
            arguments_digest: odin_domain::Digest::hash(b"arguments"),
        },
        requested_at: now,
        expires_at: now + time::Duration::hours(1),
    }
}

#[test]
fn approval_reader_surfaces_only_the_bound_sessions_requested_rows() {
    let root = std::env::temp_dir().join(format!(
        "odin-acp-backend-approvals-{}",
        super::command_id().unwrap()
    ));
    let ledger_path = root.join("ledger.sqlite3");
    std::fs::create_dir_all(&root).expect("state root");

    {
        let mut ledger = odin_ledger::Ledger::open(&ledger_path).expect("ledger");
        // This session's requested run approval: surfaced.
        ledger
            .request_approval(run_approval("approval:backend-a1", session_a()))
            .expect("request approval");
        // Another session's requested run approval: never surfaced here.
        ledger
            .request_approval(run_approval("approval:backend-b1", session_b()))
            .expect("request approval");
        // A decided row of this session: no longer decidable.
        let decided = ledger
            .request_approval(run_approval("approval:backend-a2", session_a()))
            .expect("request approval");
        ledger
            .decide_approval(
                &decided.approval_id,
                odin_ledger::approval::ApprovalDecision::Approve { evidence_ref: None },
                "operator:colin",
                time::OffsetDateTime::now_utc(),
                decided.revision,
            )
            .expect("decide approval");
        // A non-run target that even names this session: not a run approval.
        ledger
            .request_approval(odin_ledger::approval::NewApproval {
                approval_id: odin_domain::ApprovalId::new("approval:backend-a3")
                    .expect("approval id"),
                issuer: "seat:atlas".to_owned(),
                scope: odin_ledger::approval::ApprovalScope {
                    target_kind: "browserSession".to_owned(),
                    target_id: format!("run:live:{SESSION_A}"),
                    capability_id: odin_domain::CapabilityId::new("browser.interact")
                        .expect("capability id"),
                    arguments_digest: odin_domain::Digest::hash(b"arguments"),
                },
                requested_at: time::OffsetDateTime::now_utc(),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .expect("request approval");
    }

    let reader = kernel_approvals_reader(root.clone());

    let views = reader(session_a()).expect("the reader reads the ledger");
    assert_eq!(
        views.len(),
        1,
        "only the bound session's requested run row is surfaced: {views:?}"
    );
    assert_eq!(views[0].approval_id, "approval:backend-a1");
    assert_eq!(views[0].target_kind, "run");
    assert_eq!(views[0].target_id, format!("run:live:{SESSION_A}"));

    let other = reader(session_b()).expect("the reader reads the ledger");
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].approval_id, "approval:backend-b1");

    // An unreadable ledger is an error, never a silently empty answer.
    std::fs::remove_file(&ledger_path).expect("remove the ledger file");
    std::fs::create_dir_all(&ledger_path).expect("block the ledger path");
    assert!(reader(session_a()).is_err());

    let _ = std::fs::remove_dir_all(&root);
}
