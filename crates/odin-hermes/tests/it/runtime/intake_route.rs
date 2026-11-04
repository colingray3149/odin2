//! The R1 owner-DM route through the approved-intent seam: single answer, honest failure, fail-closed until bound.

use crate::runtime::fixtures::{
    discord_runtime, intent_task_id, owner_dm, FakeRoute, RecordingNotifySink,
};
use odin_ledger::Ledger;

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

/// Gateway reconnect does not replay missed DMs; backfill uses the durable cursor and normal intake checks.
#[tokio::test]
async fn dm_sent_while_the_vehicle_was_not_ready_is_answered_after_catch_up() {
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
            "author": { "id": crate::runtime::fixtures::INTENT_OWNER },
            "content": "foreign channel",
        },
        {
            "id": "1000000000000000030",
            "channel_id": crate::runtime::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": "999999999999999999" },
            "content": "foreign author",
        },
        {
            "id": "1000000000000000020",
            "channel_id": crate::runtime::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": crate::runtime::fixtures::INTENT_OWNER },
            "content": "are you there now?",
        },
        {
            "id": "1000000000000000010",
            "channel_id": crate::runtime::fixtures::INTENT_DM_CHANNEL,
            "author": { "id": crate::runtime::fixtures::INTENT_OWNER },
            "content": "earlier live dm",
        },
    ]);
    let (transport, _reads) = crate::runtime::fixtures::static_history(history).await;
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

/// Counts the clears it is asked for.
#[derive(Default)]
struct CountsClears(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl odin_hermes::runtime::OwnerDecisionRoute for CountsClears {
    async fn try_decision(
        &self,
        _message: odin_hermes::runtime::AuthenticatedOwnerMessage,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn clear(&self) -> Result<(), String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// His `/clear` waited in the queue with a question (the conversation was not
/// bound when they arrived): it is the command, run once and answered, and
/// the question alone goes to the fresh session.
#[tokio::test]
async fn a_clear_queued_with_other_messages_is_a_command_not_text() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = discord_runtime(
        dir.path(),
        Ledger::open(dir.path().join("conversation.db")).unwrap(),
        odin_domain::EffectClass::R1,
    );
    let sink = std::sync::Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    for (id, text) in [
        ("1000000000000000070", "which model are you running on?"),
        ("1000000000000000071", "/clear"),
    ] {
        let queued = runtime.admit_message(&owner_dm(id, text)).unwrap();
        assert_eq!(queued["status"], "queued", "{queued}");
    }
    let route = FakeRoute::answering();
    let clears = std::sync::Arc::new(CountsClears::default());
    runtime.set_approved_intent_route(route.clone());
    runtime.set_owner_decision_route(clears.clone());

    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 2);
    assert_eq!(clears.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        route.execution_contents(),
        ["which model are you running on?"],
        "the clear never reaches the model as text"
    );
    assert_eq!(*sink.calls.lock(), ["Cleared. Fresh start."]);
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0, "settled");
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
            crate::runtime::fixtures::INTENT_DM_CHANNEL
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
    // The decision route no longer matches: nothing decides any more.
    runtime.set_owner_decision_route(std::sync::Arc::new(DecidesOnce(String::new())));
    let history = serde_json::json!([{
        "id": "1000000000000000060",
        "channel_id": crate::runtime::fixtures::INTENT_DM_CHANNEL,
        "author": { "id": crate::runtime::fixtures::INTENT_OWNER },
        "content": "no",
    }]);
    let (transport, _reads) = crate::runtime::fixtures::static_history(history).await;
    runtime.set_discord_catch_up_transport(transport);
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
                backlog.push(crate::runtime::fixtures::history_message(
                    &id,
                    "999999999999999999",
                    "not the owner",
                ));
                foreign_ids.push(id);
            }
        }
        let id = (base + index * 100).to_string();
        backlog.push(crate::runtime::fixtures::history_message(
            &id,
            crate::runtime::fixtures::INTENT_OWNER,
            &format!("catch up {index:03}"),
        ));
        owner_ids.push(id);
    }
    let history = crate::runtime::fixtures::paginated_history(backlog).await;
    runtime.set_discord_catch_up_transport(history);

    runtime.catch_up_owner_dms().await.unwrap();

    // Every contiguous owner message became durable work, oldest to
    // newest; the foreign author never did and never claimed the cursor.
    let store = runtime.store();
    for id in &owner_ids {
        assert!(
            store
                .message_claim(crate::runtime::fixtures::INTENT_DM_CHANNEL, id)
                .unwrap()
                .is_some(),
            "owner message {id} must be durable after catch-up"
        );
    }
    for id in foreign_ids {
        assert!(store
            .message_claim(crate::runtime::fixtures::INTENT_DM_CHANNEL, &id)
            .unwrap()
            .is_none());
    }
    assert_eq!(
        store
            .latest_discord_message_id(crate::runtime::fixtures::INTENT_DM_CHANNEL)
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
    let sink = std::sync::Arc::new(crate::runtime::fixtures::RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    let say = odin_domain::CommandId::new("command:say-1").unwrap();

    sink.fail_next(odin_hermes::discord::DiscordSendError::Unreachable);
    assert!(runtime
        .admit_surface_line("via laptop", &say, "what's on today?")
        .is_err());
    let first = runtime
        .admit_surface_line("via laptop", &say, "what's on today?")
        .unwrap();
    assert_eq!(first["status"], "queued", "{first}");
    let retry = runtime
        .admit_surface_line("via laptop", &say, "what's on today?")
        .unwrap();
    assert_eq!(retry["status"], "duplicate", "{retry}");
    assert_eq!(retry["task"], first["task"]);
    assert_eq!(
        sink.calls.lock().clone(),
        vec!["the owner (via laptop): what's on today?".to_owned()],
        "one mirror"
    );
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 1);
    assert_eq!(route.count(), 1);

    let yes = odin_domain::CommandId::new("command:say-2").unwrap();
    runtime
        .store()
        .record_surface_mirror(&yes, "1000000000000000099", crate::runtime::fixtures::now())
        .unwrap();
    let interrupted = runtime
        .admit_surface_line("via laptop", &yes, "yes")
        .unwrap();
    assert_eq!(interrupted["status"], "interrupted", "{interrupted}");
    assert_eq!(sink.calls.lock().len(), 1, "no second mirror");
    assert_eq!(runtime.reconcile_admitted_intents().unwrap(), 0);

    // A line that only opens with a decision word is no decision: admitted.
    let sure = odin_domain::CommandId::new("command:say-3").unwrap();
    runtime
        .store()
        .record_surface_mirror(
            &sure,
            "1000000000000000098",
            crate::runtime::fixtures::now(),
        )
        .unwrap();
    let admitted = runtime
        .admit_surface_line("via laptop", &sure, "sure, do the cheaper one")
        .unwrap();
    assert_eq!(admitted["status"], "queued", "{admitted}");

    // Reserved but never recorded (cut off between reserve and record): the
    // retry never posts a second mirror.
    let cut = odin_domain::CommandId::new("command:say-4").unwrap();
    assert!(runtime
        .store()
        .reserve_surface_say(&cut, crate::runtime::fixtures::now())
        .unwrap());
    let refused = runtime
        .admit_surface_line("via laptop", &cut, "hello")
        .unwrap();
    assert_eq!(refused["status"], "interrupted", "{refused}");
    assert_eq!(sink.calls.lock().len(), 1, "never posted again");

    // An unreadable response may follow a successful post; retry must not create another mirror.
    let unread = odin_domain::CommandId::new("command:say-5").unwrap();
    sink.fail_next(odin_hermes::discord::DiscordSendError::Encoding(
        "scripted unreadable reply".to_owned(),
    ));
    assert!(runtime
        .admit_surface_line("via laptop", &unread, "book tea at 3")
        .is_err());
    let retried = runtime
        .admit_surface_line("via laptop", &unread, "book tea at 3")
        .unwrap();
    assert_eq!(retried["status"], "interrupted", "{retried}");
    assert_eq!(sink.calls.lock().len(), 1, "never posted again");
}
