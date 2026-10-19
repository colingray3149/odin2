//! The R1 owner-DM route through the approved-intent seam: single answer, honest failure, fail-closed until bound.

use crate::fixtures::{discord_runtime, intent_task_id, owner_dm, FakeRoute, RecordingNotifySink};
use odin_ledger::Ledger;
use std::time::{Duration, Instant};

#[test]
fn r1_owner_dm_answers_once_through_the_route_and_never_renders_the_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());

    let projection = runtime
        .admit_message(&owner_dm("1000000000000000010", "Hello"))
        .unwrap();
    assert_eq!(projection["status"], "queued", "projection: {projection}");
    assert!(projection["task"]
        .as_str()
        .unwrap()
        .starts_with("command:discord-intent:"));

    // The receipt the admit published is internal: the pump drains and
    // commits it without a send. The transport has no credential, so any
    // rendered line would fail the pump typed — Ok proves nothing rendered.
    assert!(runtime.pump_status_egress(8).unwrap() >= 1);

    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(route.count(), 1, "exactly one route execution");
    let execution = route.sole_execution();
    assert_eq!(execution.content, "Hello");
    assert_eq!(
        execution.command_id,
        intent_task_id(&projection).to_string()
    );

    let row = runtime
        .store()
        .task(&intent_task_id(&projection))
        .unwrap()
        .unwrap();
    assert_eq!(
        row.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    );
    assert_eq!(
        row.terminal_result.unwrap()["status"],
        "executed",
        "the settle projection carries the route outcome"
    );

    // A replayed DM (same source id) resolves to the original task and
    // never duplicates the side effect or the answer.
    let replay = runtime
        .admit_message(&owner_dm("1000000000000000010", "Hello"))
        .unwrap();
    assert_eq!(replay["status"], "duplicate");
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 1, "no second execution for a duplicate");
    assert!(runtime.pump_status_egress(8).is_ok());
}
#[test]
fn route_failure_settles_failed_honestly_never_completed() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("conversation.db");
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(&ledger_path).unwrap(),
        odin_domain::EffectClass::R1,
    );
    runtime.set_approved_intent_route(FakeRoute::failing("the conversation session errored: test"));
    let sink = std::sync::Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    let projection = runtime
        .admit_message(&owner_dm("1000000000000000020", "Hello"))
        .unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(sink.calls.lock().len(), 1);
    let deliveries = Ledger::open(&ledger_path)
        .unwrap()
        .conversation_deliveries()
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    let state: serde_json::Value = serde_json::from_str(&deliveries[0].state_json).unwrap();
    assert_eq!(state["phase"], "committed");
    assert_eq!(state["key"], intent_task_id(&projection).to_string());
    assert_eq!(state["target"][0], sink.calls.lock()[0]);
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(sink.calls.lock().len(), 1);
    let row = runtime
        .store()
        .task(&intent_task_id(&projection))
        .unwrap()
        .unwrap();
    assert_eq!(
        row.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Failed)
    );
    assert!(
        row.terminal_result.unwrap()["reason"]
            .as_str()
            .unwrap()
            .contains("the conversation session errored"),
        "the typed route failure is the durable outcome"
    );
    // No raw receipt on the failure path either.
    assert!(runtime.pump_status_egress(8).is_ok());
}
#[test]
fn unbound_route_holds_admitted_intents_fail_closed_until_bound() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let projection = runtime
        .admit_message(&owner_dm("1000000000000000030", "Hello"))
        .unwrap();
    assert_eq!(projection["status"], "queued");
    assert_eq!(
        runtime.reconcile_admitted_intents().unwrap(),
        0,
        "fail closed: no route, no execution, no fabricated settle"
    );
    let row = runtime
        .store()
        .task(&intent_task_id(&projection))
        .unwrap()
        .unwrap();
    assert!(row.terminal_status.is_none(), "held, not settled failed");

    // Binding the real route releases the held intent on the next tick.
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(route.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_dm_wakes_reconcile_without_the_recovery_tick() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    runtime.wait_for_reconcile_wake().await;

    let admitted_at = Instant::now();
    let projection = runtime
        .admit_message(&owner_dm("1000000000000000040", "Measure latency"))
        .unwrap();
    assert_eq!(projection["status"], "queued");
    tokio::time::timeout(
        Duration::from_millis(500),
        runtime.wait_for_reconcile_wake(),
    )
    .await
    .expect("admission wakes reconcile without the recovery tick");

    let worker = {
        let runtime = runtime.clone();
        tokio::task::spawn_blocking(move || runtime.reconcile_admitted_intents().unwrap())
    };
    assert_eq!(worker.await.unwrap(), 1);
    let reply_sent = admitted_at.elapsed();
    assert_eq!(route.count(), 1);
    eprintln!("event-driven DM->first-model-token={reply_sent:?} DM->reply-sent={reply_sent:?}");
    assert!(
        reply_sent < Duration::from_millis(500),
        "admission must not wait for the five-second recovery tick: {reply_sent:?}"
    );
}

/// Gateway reconnect does not replay missed DMs; backfill uses the durable cursor and normal intake checks.
#[tokio::test]
async fn dm_sent_while_the_vehicle_was_not_ready_is_answered_after_catch_up() {
    use odin_hermes::discord::{DiscordCredential, DiscordRestTransport, SecretToken};
    use std::sync::{Arc, Mutex};

    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );

    runtime
        .admit_message(&owner_dm("1000000000000000010", "earlier live dm"))
        .unwrap();

    // The REST history window Discord would return (newest first): a
    // foreign author in the channel, the missed owner DM, and the
    // already-processed id from BEFORE the cursor.
    let history = serde_json::json!([
        {
            "id": "1000000000000000040",
            "channel_id": "1000000000000000999",
            "author": { "id": crate::fixtures::INTENT_OWNER },
            "content": "foreign channel",
        },
        {
            "id": "1000000000000000030",
            "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": "999999999999999999" },
            "content": "foreign author",
        },
        {
            "id": "1000000000000000020",
            "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": crate::fixtures::INTENT_OWNER },
            "content": "are you there now?",
        },
        {
            "id": "1000000000000000010",
            "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": crate::fixtures::INTENT_OWNER },
            "content": "earlier live dm",
        },
    ]);
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let state = captured.clone();
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::get(move |_path: axum::extract::Path<String>| {
            let state = state.clone();
            async move {
                if let Ok(mut calls) = state.lock() {
                    calls.push("fetched".to_owned());
                }
                axum::Json(history.clone())
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let transport = Arc::new(
        DiscordRestTransport::with_api_base(
            DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                SecretToken::new("test-token").unwrap(),
            ),
            reqwest::Client::new(),
            format!("http://{address}"),
        )
        .unwrap(),
    );
    runtime.set_discord_catch_up_transport(transport);

    // The vehicle is NOT ready (no route bound): the catch-up still admits
    // durably — the reconciler holds the queue fail-closed until bound.
    let fetched = runtime.catch_up_owner_dms().await.unwrap();
    assert_eq!(fetched, 4, "the whole bounded window was fetched");

    // Backfill admits only missed owner messages, rejecting foreign sources and duplicate ids.
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(
        runtime.reconcile_admitted_intents().unwrap(),
        2,
        "the live DM and the caught-up DM both drain"
    );
    assert_eq!(
        route.execution_contents(),
        vec![
            "earlier live dm".to_owned(),
            "are you there now?".to_owned(),
        ],
        "exactly the live DM and the caught-up DM executed, in order"
    );

    // A replayed catch-up fetch resolves every id duplicate: no second
    // answer for any already-processed message.
    let refetched = runtime.catch_up_owner_dms().await.unwrap();
    assert_eq!(refetched, 4);
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(
        route.count(),
        2,
        "no new execution for any replayed duplicate"
    );
}

#[tokio::test]
async fn accepted_while_vehicle_not_ready_is_answered_by_the_ready_drain() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R3,
    );

    // The DM arrives while the vehicle is NOT ready (no route bound).
    // Admission gates it; the paired owner message approves it (the
    // production admit path); the reconcile pass ACCEPTS it and holds it
    // fail-closed for the route.
    let projection = runtime
        .admit_message(&owner_dm("1000000000000000066", "catch me if you can"))
        .unwrap();
    assert_eq!(projection["status"], "gated", "projection: {projection}");
    // Held fail-closed while the vehicle is not ready (0 ROUTED) — but
    // the gate ACCEPTS it: the waiting-for-route durable shape.
    assert_eq!(
        runtime.reconcile_gated_tasks().unwrap(),
        0,
        "held for the route"
    );
    let task_id = crate::fixtures::intent_task_id(&projection);
    let row = runtime.store().task(&task_id).unwrap().unwrap();
    assert!(
        row.accepted_at.is_some(),
        "the crashed/waiting shape: accepted"
    );
    assert!(
        row.terminal_status.is_none(),
        "unsettled while the vehicle opens"
    );

    // The vehicle becomes ready: the route binds and the ready edge runs
    // the shared reconcile path ONCE — no new DM, no wake race.
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let gated = runtime.reconcile_gated_tasks().unwrap();
    let admitted = runtime.reconcile_admitted_intents().unwrap();
    assert!(
        gated + admitted >= 1,
        "the ready drain must route the waiting intent (gated={gated} admitted={admitted})"
    );
    assert_eq!(
        route.execution_contents(),
        vec!["catch me if you can".to_owned()],
        "answered exactly once, oldest first"
    );
    let settled = runtime.store().task(&task_id).unwrap().unwrap();
    assert_eq!(
        settled.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    );
    // Nothing further: a second drain is a no-op.
    assert_eq!(runtime.reconcile_gated_tasks().unwrap(), 0);
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 1);
}

/// Consumes exactly the message text it was built for as a decision.
struct DecidesOnce(String);

#[async_trait::async_trait]
impl odin_hermes::runtime::OwnerDecisionRoute for DecidesOnce {
    async fn try_decision(
        &self,
        message: odin_hermes::runtime::AuthenticatedOwnerMessage,
    ) -> Result<Option<String>, String> {
        Ok((message.content == self.0).then(|| "Understood — I won't do that.".to_owned()))
    }
}

#[tokio::test]
async fn a_decided_message_is_never_caught_up_as_a_new_request() {
    use odin_hermes::discord::{DiscordCredential, DiscordRestTransport, SecretToken};

    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("conversation.db");
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(&ledger_path).unwrap(),
        odin_domain::EffectClass::R1,
    );
    runtime.set_owner_decision_route(std::sync::Arc::new(DecidesOnce("no".to_owned())));
    let sink = std::sync::Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    let decided = runtime
        .admit_message(&owner_dm("1000000000000000060", "no"))
        .unwrap();
    assert_eq!(decided["status"], "decided");
    assert_eq!(sink.calls.lock().len(), 1);
    let deliveries = Ledger::open(&ledger_path)
        .unwrap()
        .conversation_deliveries()
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    let state: serde_json::Value = serde_json::from_str(&deliveries[0].state_json).unwrap();
    assert_eq!(state["phase"], "committed");
    assert_eq!(
        state["key"],
        format!(
            "discord:v1:{}:1000000000000000060",
            crate::fixtures::INTENT_DM_CHANNEL
        )
    );
    let replay = runtime
        .admit_message(&owner_dm("1000000000000000060", "no"))
        .unwrap();
    assert_eq!(replay["status"], "decided");
    assert_eq!(
        sink.calls.lock().len(),
        1,
        "same original decision never posts again"
    );
    // After the restart the approval is gone: nothing decides any more.
    runtime.set_owner_decision_route(std::sync::Arc::new(DecidesOnce(String::new())));
    let history = serde_json::json!([{
        "id": "1000000000000000060",
        "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
        "author": { "id": crate::fixtures::INTENT_OWNER },
        "content": "no",
    }]);
    let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = reads.clone();
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::get(move |_path: axum::extract::Path<String>| {
            let history = history.clone();
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { axum::Json(history) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    runtime.set_discord_catch_up_transport(std::sync::Arc::new(
        DiscordRestTransport::with_api_base(
            DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                SecretToken::new("test-token").unwrap(),
            ),
            reqwest::Client::new(),
            format!("http://{address}"),
        )
        .unwrap(),
    ));
    runtime.catch_up_owner_dms().await.unwrap();
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 0, "the decided \"no\" never became a prompt");
}

/// Catch-up crosses both page boundaries and an entirely foreign page,
/// without replaying completed owner work or losing the durable frontier.
#[tokio::test]
async fn dm_backlog_beyond_one_page_drains_every_contiguous_owner_message() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );

    let base: u64 = 2_000_000_000_000_000_000;
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    runtime
        .admit_message(&owner_dm(&(base - 100).to_string(), "before outage"))
        .unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    let mut foreign_ids = Vec::new();
    let mut owner_ids = Vec::new();
    let mut backlog = Vec::new();
    for index in 0..120u64 {
        if index == 50 {
            for offset in 1..=50 {
                let id = (base + 4900 + offset).to_string();
                backlog.push(crate::fixtures::history_message(
                    &id,
                    "999999999999999999",
                    "not the owner",
                ));
                foreign_ids.push(id);
            }
        }
        let id = (base + index * 100).to_string();
        backlog.push(crate::fixtures::history_message(
            &id,
            crate::fixtures::INTENT_OWNER,
            &format!("catch up {index:03}"),
        ));
        owner_ids.push(id);
    }
    let history = crate::fixtures::paginated_history(backlog).await;
    runtime.set_discord_catch_up_transport(history);

    runtime.catch_up_owner_dms().await.unwrap();

    // Every contiguous owner message became durable work, oldest to
    // newest; the foreign author never did and never claimed the cursor.
    let store = runtime.store();
    for id in &owner_ids {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_some(),
            "owner message {id} must be durable after catch-up"
        );
    }
    for id in foreign_ids {
        assert!(store
            .message_claim(crate::fixtures::INTENT_DM_CHANNEL, &id)
            .unwrap()
            .is_none());
    }
    assert_eq!(
        store
            .latest_discord_message_id(crate::fixtures::INTENT_DM_CHANNEL)
            .unwrap()
            .as_deref(),
        owner_ids.last().map(String::as_str),
        "the frontier is the newest owner message"
    );

    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 120);
    let expected: Vec<String> = std::iter::once("before outage".to_owned())
        .chain((0..120u64).map(|index| format!("catch up {index:03}")))
        .collect();
    assert_eq!(
        route.execution_contents(),
        expected,
        "every owner message executed exactly once, oldest first"
    );
    runtime.catch_up_owner_dms().await.unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 121, "no duplicate admission after the retry");
}

/// A real SQLite failure must stop before admitting later owner IDs;
/// clearing only that fault lets the next catch-up admit each entry once.
#[tokio::test]
async fn first_entry_persistence_failure_stops_catch_up_before_later_owner_ids() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("conversation.db");
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(&ledger_path).unwrap(),
        odin_domain::EffectClass::R1,
    );

    let base: u64 = 2_000_000_000_000_001_000;
    let first = base.to_string();
    let foreign = (base + 5).to_string();
    let second = (base + 10).to_string();
    let third = (base + 15).to_string();
    let backlog = vec![
        crate::fixtures::history_message(
            &first,
            crate::fixtures::INTENT_OWNER,
            "first after the outage",
        ),
        crate::fixtures::history_message(&foreign, "999999999999999999", "not the owner"),
        crate::fixtures::history_message(
            &second,
            crate::fixtures::INTENT_OWNER,
            "second after the outage",
        ),
        crate::fixtures::history_message(
            &third,
            crate::fixtures::INTENT_OWNER,
            "third after the outage",
        ),
    ];
    let history = crate::fixtures::paginated_history(backlog).await;
    runtime.set_discord_catch_up_transport(history);

    // The real private SQLite fault: exactly the first entry's durable
    // intake claim refuses, inside the same transaction that records its
    // task row.
    let control = Ledger::open(&ledger_path).unwrap();
    control
        .connection()
        .execute_batch(&format!(
            "CREATE TRIGGER fixture_first_intake_claim_outage
             BEFORE INSERT ON idempotency_keys
             WHEN NEW.key = 'discord:v1:{}:{first}'
             BEGIN SELECT RAISE(ABORT, 'fixture first intake claim outage'); END;",
            crate::fixtures::INTENT_DM_CHANNEL
        ))
        .unwrap();

    let failed = runtime.catch_up_owner_dms().await;
    assert!(
        failed.is_err(),
        "the first entry's persistence failure must surface, not be skipped: {failed:?}"
    );

    // Nothing became durable: no later owner id admitted while the first
    // cannot persist, the foreign author claimed nothing, and the durable
    // frontier never moved past the stranded first entry.
    let store = runtime.store();
    for id in [&first, &foreign, &second, &third] {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_none(),
            "{id} must not be durable while the first entry cannot persist"
        );
    }
    assert_eq!(
        store
            .latest_discord_message_id(crate::fixtures::INTENT_DM_CHANNEL)
            .unwrap(),
        None,
        "later ids and the foreign refusal must not strand the failed owner work"
    );

    // Clear ONLY the test fault and retry: every entry admits exactly once.
    control
        .connection()
        .execute_batch("DROP TRIGGER fixture_first_intake_claim_outage;")
        .unwrap();
    drop(control);
    runtime.catch_up_owner_dms().await.unwrap();
    for id in [&first, &second, &third] {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_some(),
            "{id} admits once the fault clears"
        );
    }
    assert!(store
        .message_claim(crate::fixtures::INTENT_DM_CHANNEL, &foreign)
        .unwrap()
        .is_none());

    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 3);
    assert_eq!(
        route.execution_contents(),
        vec![
            "first after the outage".to_owned(),
            "second after the outage".to_owned(),
            "third after the outage".to_owned(),
        ],
        "every owner message executes once, oldest first"
    );
    runtime.catch_up_owner_dms().await.unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 3, "no entry admits twice");
}

/// A failed handled-decision marker must stop catch-up before later
/// owner work; clearing only that fault lets the contiguous drain resume.
#[tokio::test]
async fn first_decision_marker_storage_failure_stops_catch_up_before_later_owner_ids() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("conversation.db");
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(&ledger_path).unwrap(),
        odin_domain::EffectClass::R1,
    );
    runtime.set_owner_decision_route(std::sync::Arc::new(DecidesOnce("no".to_owned())));
    runtime
        .bind_notify_sink(std::sync::Arc::new(RecordingNotifySink::default()))
        .unwrap();

    let base: u64 = 2_000_000_000_000_002_000;
    let first = base.to_string();
    let foreign = (base + 5).to_string();
    let later = (base + 10).to_string();
    let backlog = vec![
        crate::fixtures::history_message(&first, crate::fixtures::INTENT_OWNER, "no"),
        crate::fixtures::history_message(&foreign, "999999999999999999", "not the owner"),
        crate::fixtures::history_message(&later, crate::fixtures::INTENT_OWNER, "the later work"),
    ];
    let history = crate::fixtures::paginated_history(backlog).await;
    runtime.set_discord_catch_up_transport(history);

    // The real private SQLite fault: exactly the first decision's durable
    // handled-marker claim refuses.
    let control = Ledger::open(&ledger_path).unwrap();
    control
        .connection()
        .execute_batch(&format!(
            "CREATE TRIGGER fixture_first_decision_marker_outage
             BEFORE INSERT ON idempotency_keys
             WHEN NEW.key = 'discord:v1:{}:{first}'
             BEGIN SELECT RAISE(ABORT, 'fixture first decision marker outage'); END;",
            crate::fixtures::INTENT_DM_CHANNEL
        ))
        .unwrap();

    let failed = runtime.catch_up_owner_dms().await;
    assert!(
        failed.is_err(),
        "the first decision's marker failure must surface, not be skipped: {failed:?}"
    );

    // Nothing became durable: the decision has no marker, no later owner
    // id admitted, the foreign author claimed nothing, and the frontier
    // never moved past the failed decision.
    let store = runtime.store();
    for id in [&first, &foreign, &later] {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_none(),
            "{id} must not be durable while the decision marker cannot persist"
        );
    }
    assert_eq!(
        store
            .latest_discord_message_id(crate::fixtures::INTENT_DM_CHANNEL)
            .unwrap(),
        None,
        "later owner work must not strand the failed decision behind the cursor"
    );

    // Clear ONLY the test fault and retry: the decision marks handled and
    // the later owner work admits exactly once.
    control
        .connection()
        .execute_batch("DROP TRIGGER fixture_first_decision_marker_outage;")
        .unwrap();
    drop(control);
    runtime.catch_up_owner_dms().await.unwrap();
    assert!(store
        .message_claim(crate::fixtures::INTENT_DM_CHANNEL, &first)
        .unwrap()
        .is_some());
    assert!(store
        .message_claim(crate::fixtures::INTENT_DM_CHANNEL, &later)
        .unwrap()
        .is_some());
    assert!(store
        .message_claim(crate::fixtures::INTENT_DM_CHANNEL, &foreign)
        .unwrap()
        .is_none());

    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(
        route.execution_contents(),
        vec!["the later work".to_owned()],
        "the decided \"no\" never becomes a prompt"
    );
    runtime.catch_up_owner_dms().await.unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 1, "no entry admits twice");
}

/// An owner message with no text and no supported attachment (a sticker,
/// whitespace, or a file Discord serves from a foreign host) is refused by
/// intake before anything is recorded. A full page of them must not strand
/// the owner's later work behind the durable frontier, while a real
/// storage failure on that later work still stops the drain.
#[tokio::test]
async fn contentless_owner_messages_never_strand_later_owner_work() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("conversation.db");
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(&ledger_path).unwrap(),
        odin_domain::EffectClass::R1,
    );

    let base: u64 = 2_000_000_000_000_003_000;
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let before = (base - 100).to_string();
    runtime
        .admit_message(&owner_dm(&before, "before outage"))
        .unwrap();
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);

    // Exactly one full page of contentless owner messages, then real work.
    let mut contentless = Vec::new();
    let mut backlog = Vec::new();
    for index in 0..u64::from(odin_hermes::discord::DM_CATCH_UP_LIMIT) {
        let id = (base + index).to_string();
        let entry = match index % 3 {
            0 => serde_json::json!({
                "id": id,
                "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
                "author": { "id": crate::fixtures::INTENT_OWNER },
                "content": "",
                "sticker_items": [{ "id": "1000000000000000500", "name": "wave", "format_type": 1 }],
            }),
            1 => crate::fixtures::history_message(&id, crate::fixtures::INTENT_OWNER, " \n\t "),
            _ => serde_json::json!({
                "id": id,
                "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
                "author": { "id": crate::fixtures::INTENT_OWNER },
                "content": "",
                "attachments": [{
                    "id": "1000000000000000501",
                    "filename": "photo.png",
                    "size": 10,
                    "url": "https://example.com/photo.png",
                }],
            }),
        };
        backlog.push(entry);
        contentless.push(id);
    }
    let first = (base + 1_000).to_string();
    let foreign = (base + 1_005).to_string();
    let second = (base + 1_010).to_string();
    backlog.push(crate::fixtures::history_message(
        &first,
        crate::fixtures::INTENT_OWNER,
        "first real work",
    ));
    backlog.push(crate::fixtures::history_message(
        &foreign,
        "999999999999999999",
        "not the owner",
    ));
    backlog.push(crate::fixtures::history_message(
        &second,
        crate::fixtures::INTENT_OWNER,
        "second real work",
    ));
    let fetched_total = backlog.len();
    let history = crate::fixtures::paginated_history(backlog).await;
    runtime.set_discord_catch_up_transport(history);

    // A real SQLite fault on the first real work: the drain stops before
    // any later owner id becomes durable.
    let control = Ledger::open(&ledger_path).unwrap();
    control
        .connection()
        .execute_batch(&format!(
            "CREATE TRIGGER fixture_real_work_intake_claim_outage
             BEFORE INSERT ON idempotency_keys
             WHEN NEW.key = 'discord:v1:{}:{first}'
             BEGIN SELECT RAISE(ABORT, 'fixture real work intake claim outage'); END;",
            crate::fixtures::INTENT_DM_CHANNEL
        ))
        .unwrap();
    let failed = runtime.catch_up_owner_dms().await;
    assert!(
        failed.is_err(),
        "a storage failure on real work must surface: {failed:?}"
    );
    let store = runtime.store();
    for id in [&first, &foreign, &second] {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_none(),
            "{id} must not be durable while earlier owner work cannot persist"
        );
    }
    assert_eq!(
        store
            .latest_discord_message_id(crate::fixtures::INTENT_DM_CHANNEL)
            .unwrap()
            .as_deref(),
        Some(before.as_str()),
        "the frontier stays before the failed owner work"
    );

    // Clear ONLY the storage fault: the contentless page is passed over and
    // every real owner message admits exactly once, oldest first.
    control
        .connection()
        .execute_batch("DROP TRIGGER fixture_real_work_intake_claim_outage;")
        .unwrap();
    drop(control);
    let caught_up = runtime.catch_up_owner_dms().await;
    assert_eq!(
        caught_up,
        Ok(fetched_total),
        "contentless owner messages must not stop the catch-up"
    );
    for id in [&first, &second] {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_some(),
            "owner work {id} must be durable after catch-up"
        );
    }
    for id in contentless.iter().chain([&foreign]) {
        assert!(
            store
                .message_claim(crate::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_none(),
            "{id} never becomes durable work"
        );
    }
    assert_eq!(
        store
            .latest_discord_message_id(crate::fixtures::INTENT_DM_CHANNEL)
            .unwrap()
            .as_deref(),
        Some(second.as_str()),
        "the frontier is the newest owner work"
    );
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 2);
    assert_eq!(
        route.execution_contents(),
        vec![
            "before outage".to_owned(),
            "first real work".to_owned(),
            "second real work".to_owned(),
        ],
        "every real owner message executes once, oldest first"
    );

    // The durable frontier moved past the contentless page: a retry
    // fetches nothing and admits nothing again.
    assert_eq!(runtime.catch_up_owner_dms().await, Ok(0));
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);
    assert_eq!(route.count(), 3, "no entry admits twice");
}

#[tokio::test]
async fn the_owner_thread_is_the_channel_as_discord_shows_it() {
    use odin_hermes::discord::{DiscordCredential, DiscordRestTransport, SecretToken};

    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let history = serde_json::json!([
        {
            "id": "1000000000000000072",
            "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": "999999999999999999", "bot": true },
            "content": "Booked tea for 3:00 PM.",
            "attachments": [{
                "id": "1000000000000000073",
                "filename": "receipt.pdf",
                "size": 10,
                "url": "https://cdn.discordapp.com/attachments/1/2/receipt.pdf",
            }],
        },
        {
            "id": "1000000000000000071",
            "channel_id": crate::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": crate::fixtures::INTENT_OWNER },
            "content": "book tea at 3",
        },
    ]);
    let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = reads.clone();
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::get(move |_path: axum::extract::Path<String>| {
            let history = history.clone();
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { axum::Json(history) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    runtime.set_discord_catch_up_transport(std::sync::Arc::new(
        DiscordRestTransport::with_api_base(
            DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                SecretToken::new("test-token").unwrap(),
            ),
            reqwest::Client::new(),
            format!("http://{address}"),
        )
        .unwrap(),
    ));
    let thread = runtime.owner_thread(None).await.expect("the channel reads");
    let shown: Vec<(&str, bool, &str, Vec<String>)> = thread
        .iter()
        .map(|line| {
            (
                line.id.as_str(),
                line.from_owner,
                line.text.as_str(),
                line.files.clone(),
            )
        })
        .collect();
    assert_eq!(
        shown,
        vec![
            ("1000000000000000071", true, "book tea at 3", Vec::new()),
            (
                "1000000000000000072",
                false,
                "Booked tea for 3:00 PM.",
                vec!["receipt.pdf".to_owned()]
            ),
        ]
    );
    // Q37 (L7 soak: p95 2.3 s, >15 s during turns): later reads are served
    // from the lines the runtime saw, not Discord.
    runtime
        .admit_message(&owner_dm("1000000000000000080", "and a scone"))
        .unwrap();
    let later = runtime
        .owner_thread(Some("1000000000000000072"))
        .await
        .expect("served");
    assert_eq!(
        later
            .iter()
            .map(|line| (line.from_owner, line.text.as_str()))
            .collect::<Vec<_>>(),
        vec![(true, "and a scone")]
    );
    assert_eq!(
        reads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one Discord read"
    );
}

/// Retries reuse posted message ids, and uncertain posts are never repeated or reinterpreted as decisions.
#[test]
fn a_retried_say_is_mirrored_and_admitted_once() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open_in_memory().unwrap(),
        odin_domain::EffectClass::R1,
    );
    let route = FakeRoute::answering();
    runtime.set_approved_intent_route(route.clone());
    let sink = std::sync::Arc::new(crate::fixtures::RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    let say = odin_domain::CommandId::new("command:say-1").unwrap();

    sink.fail_next(odin_hermes::discord::DiscordSendError::Unreachable);
    assert!(runtime
        .admit_surface_line("laptop", &say, "what's on today?")
        .is_err());
    let first = runtime
        .admit_surface_line("laptop", &say, "what's on today?")
        .unwrap();
    assert_eq!(first["status"], "queued", "{first}");
    let retry = runtime
        .admit_surface_line("laptop", &say, "what's on today?")
        .unwrap();
    assert_eq!(retry["status"], "duplicate", "{retry}");
    assert_eq!(retry["task"], first["task"]);
    assert_eq!(
        sink.calls.lock().clone(),
        vec!["Colin (via laptop): what's on today?".to_owned()],
        "one mirror"
    );
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(route.count(), 1);

    let yes = odin_domain::CommandId::new("command:say-2").unwrap();
    runtime
        .store()
        .record_surface_mirror(&yes, "1000000000000000099", crate::fixtures::now())
        .unwrap();
    let interrupted = runtime.admit_surface_line("laptop", &yes, "yes").unwrap();
    assert_eq!(interrupted["status"], "interrupted", "{interrupted}");
    assert_eq!(sink.calls.lock().len(), 1, "no second mirror");
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);

    // A line that only opens with a decision word is no decision: admitted.
    let sure = odin_domain::CommandId::new("command:say-3").unwrap();
    runtime
        .store()
        .record_surface_mirror(&sure, "1000000000000000098", crate::fixtures::now())
        .unwrap();
    let admitted = runtime
        .admit_surface_line("laptop", &sure, "sure, do the cheaper one")
        .unwrap();
    assert_eq!(admitted["status"], "queued", "{admitted}");

    // Reserved but never recorded (cut off between reserve and record): the
    // retry never posts a second mirror.
    let cut = odin_domain::CommandId::new("command:say-4").unwrap();
    assert!(runtime
        .store()
        .reserve_surface_say(&cut, crate::fixtures::now())
        .unwrap());
    let refused = runtime.admit_surface_line("laptop", &cut, "hello").unwrap();
    assert_eq!(refused["status"], "interrupted", "{refused}");
    assert_eq!(sink.calls.lock().len(), 1, "never posted again");

    // An unreadable response may follow a successful post; retry must not create another mirror.
    let unread = odin_domain::CommandId::new("command:say-5").unwrap();
    sink.fail_next(odin_hermes::discord::DiscordSendError::Encoding);
    assert!(runtime
        .admit_surface_line("laptop", &unread, "book tea at 3")
        .is_err());
    let retried = runtime
        .admit_surface_line("laptop", &unread, "book tea at 3")
        .unwrap();
    assert_eq!(retried["status"], "interrupted", "{retried}");
    assert_eq!(sink.calls.lock().len(), 1, "never posted again");
}
