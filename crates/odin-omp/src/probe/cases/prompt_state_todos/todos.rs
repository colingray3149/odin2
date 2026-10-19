//! Case 5 owner: todo seed/update synchronization and its normalized
//! state/event contract.

use super::shared::*;
use super::*;

pub(super) struct TodoSeedUpdateCase;

#[async_trait]
impl ConformanceCase for TodoSeedUpdateCase {
    fn id(&self) -> ConformanceCaseId {
        TODO_SEED_UPDATE
    }

    fn name(&self) -> &'static str {
        "todo_seed_update"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_todo_seed_update(context).await
    }
}

async fn run_todo_seed_update(context: &CaseContext) -> CaseOutcome {
    let mut driver = match spawn_driver(context).await {
        Ok(driver) => driver,
        Err(failure) => {
            return CaseOutcome::fail("todo synchronization could not start", vec![failure]);
        }
    };
    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    if let Err(failure) = todo_seed_update(&mut driver, &mut failures, &mut evidence).await {
        failures.push(failure);
    }
    finish_case(
        driver,
        "todo_seed_update",
        "strict todo seed and update remained normalized in responses and state",
        "todo seed/update contract failed",
        failures,
        evidence,
    )
    .await
}

async fn todo_seed_update(
    driver: &mut RawRpcDriver,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) -> Result<(), CaseFailure> {
    let seed = seed_todos();
    let updated = updated_todos();
    let seed_value =
        serde_json::to_value(&seed).map_err(|error| rpc_error("todo_seed_encode", error))?;
    let updated_value =
        serde_json::to_value(&updated).map_err(|error| rpc_error("todo_update_encode", error))?;
    let start = driver.transcript().len();

    let seed_id = driver
        .send("set_todos", json!({ "phases": seed_value }))
        .await
        .map_err(|error| rpc_error("todo_seed_send", error))?;
    let seed_response = driver
        .wait_for_response(&seed_id, "set_todos", deadline())
        .await
        .map_err(|error| rpc_error("todo_seed_response", error))?;
    let seed_from_response = strict_todos(
        &seed_response,
        &seed_id,
        "set_todos",
        "seed response",
        &seed,
        failures,
    );

    let seed_state_id = driver
        .send("get_state", json!({}))
        .await
        .map_err(|error| rpc_error("todo_seed_state_send", error))?;
    let seed_state = driver
        .wait_for_response(&seed_state_id, "get_state", deadline())
        .await
        .map_err(|error| rpc_error("todo_seed_state_response", error))?;
    let seed_from_state = strict_todos(
        &seed_state,
        &seed_state_id,
        "get_state",
        "state after seed",
        &seed,
        failures,
    );

    let update_id = driver
        .send("set_todos", json!({ "phases": updated_value }))
        .await
        .map_err(|error| rpc_error("todo_update_send", error))?;
    let update_response = driver
        .wait_for_response(&update_id, "set_todos", deadline())
        .await
        .map_err(|error| rpc_error("todo_update_response", error))?;
    let update_from_response = strict_todos(
        &update_response,
        &update_id,
        "set_todos",
        "update response",
        &updated,
        failures,
    );

    let update_state_id = driver
        .send("get_state", json!({}))
        .await
        .map_err(|error| rpc_error("todo_update_state_send", error))?;
    let update_state = driver
        .wait_for_response(&update_state_id, "get_state", deadline())
        .await
        .map_err(|error| rpc_error("todo_update_state_response", error))?;
    let update_from_state = strict_todos(
        &update_state,
        &update_state_id,
        "get_state",
        "state after update",
        &updated,
        failures,
    );

    if let (Some(response), Some(state)) = (seed_from_response.as_ref(), seed_from_state.as_ref()) {
        require(
            response == state,
            "todo_seed_durable",
            "seed response and following state differed",
            failures,
        );
    }
    if let (Some(response), Some(state)) =
        (update_from_response.as_ref(), update_from_state.as_ref())
    {
        require(
            response == state,
            "todo_update_durable",
            "update response and following state differed",
            failures,
        );
    }
    if let (Some(seed), Some(update)) = (seed_from_state.as_ref(), update_from_state.as_ref()) {
        require(
            task_status(seed, "Capture raw frames") == Some(TodoStatus::InProgress)
                && task_status(update, "Capture raw frames") == Some(TodoStatus::Completed),
            "todo_completed_transition",
            "Capture raw frames did not transition in_progress -> completed",
            failures,
        );
        require(
            task_status(seed, "Correlate request ids") == Some(TodoStatus::Pending)
                && task_status(update, "Correlate request ids") == Some(TodoStatus::InProgress),
            "todo_active_transition",
            "Correlate request ids did not transition pending -> in_progress",
            failures,
        );
        for status in TodoStatus::ALL {
            require(
                update
                    .iter()
                    .flat_map(|phase| phase.tasks.iter())
                    .any(|task| task.status == status),
                "todo_distinct_statuses",
                format!("updated state omitted {status:?}"),
                failures,
            );
        }
    }

    let frames = driver.transcript();
    let seed_event = find_required(
        frames,
        start,
        frames.len(),
        "todo_seed_event",
        "seed set_todos response",
        failures,
        |value| response_matches(value, &seed_id, "set_todos"),
    );
    let seed_state_event = find_after(
        frames,
        seed_event,
        frames.len(),
        "todo_seed_state_event",
        "state response after seed",
        failures,
        |value| response_matches(value, &seed_state_id, "get_state"),
    );
    let update_event = find_after(
        frames,
        seed_state_event,
        frames.len(),
        "todo_update_event",
        "update set_todos response",
        failures,
        |value| response_matches(value, &update_id, "set_todos"),
    );
    let update_state_event = find_after(
        frames,
        update_event,
        frames.len(),
        "todo_update_state_event",
        "state response after update",
        failures,
        |value| response_matches(value, &update_state_id, "get_state"),
    );
    require(
        update_state_event.is_some(),
        "todo_event_order",
        "seed/update response-state event order was incomplete",
        failures,
    );
    forbid_agent_events(frames, start, frames.len(), "set_todos sequence", failures);

    push_json_evidence(
        evidence,
        failures,
        "todo_snapshots",
        "seed-update.json",
        &json!({
            "seed_response": seed_response.value().get("data").cloned().unwrap_or(Value::Null),
            "seed_state": seed_state.value().get("data").cloned().unwrap_or(Value::Null),
            "update_response": update_response.value().get("data").cloned().unwrap_or(Value::Null),
            "update_state": update_state.value().get("data").cloned().unwrap_or(Value::Null),
        }),
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TodoPhase {
    name: String,
    tasks: Vec<TodoTask>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TodoTask {
    content: String,
    status: TodoStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocker: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TodoStatus {
    Pending,
    InProgress,
    Completed,
    Abandoned,
    Blocked,
}

impl TodoStatus {
    const ALL: [Self; 5] = [
        Self::Pending,
        Self::InProgress,
        Self::Completed,
        Self::Abandoned,
        Self::Blocked,
    ];
}

fn seed_todos() -> Vec<TodoPhase> {
    todo_fixture(TodoStatus::InProgress, TodoStatus::Pending)
}

fn updated_todos() -> Vec<TodoPhase> {
    todo_fixture(TodoStatus::Completed, TodoStatus::InProgress)
}

fn todo_fixture(capture: TodoStatus, correlate: TodoStatus) -> Vec<TodoPhase> {
    vec![
        TodoPhase {
            name: "Protocol".to_owned(),
            tasks: vec![
                task("Capture raw frames", capture),
                task("Correlate request ids", correlate),
                task("Publish normalized state", TodoStatus::Pending),
            ],
        },
        TodoPhase {
            name: "Disposition".to_owned(),
            tasks: vec![
                task("Keep completed effect", TodoStatus::Completed),
                task("Retire stale branch", TodoStatus::Abandoned),
                TodoTask {
                    content: "Wait for approval".to_owned(),
                    status: TodoStatus::Blocked,
                    blocker: Some("approval pending".to_owned()),
                },
            ],
        },
    ]
}

fn task(content: &str, status: TodoStatus) -> TodoTask {
    TodoTask {
        content: content.to_owned(),
        status,
        blocker: None,
    }
}

fn strict_todos(
    frame: &DecodedRpcFrame,
    id: &str,
    command: &str,
    label: &str,
    expected: &[TodoPhase],
    failures: &mut Vec<CaseFailure>,
) -> Option<Vec<TodoPhase>> {
    let data = response_data(frame, id, command, label, failures)?;
    if command == "set_todos" {
        require(
            data.as_object()
                .is_some_and(|object| object.len() == 1 && object.contains_key("todoPhases")),
            "todo_response_shape",
            format!("{label} data contained fields other than todoPhases"),
            failures,
        );
    }
    let Some(value) = data.get("todoPhases") else {
        failures.push(failure(
            "todo_response_shape",
            format!("{label} omitted data.todoPhases"),
        ));
        return None;
    };
    match serde_json::to_value(expected) {
        Ok(expected) => require(
            value == &expected,
            "todo_normalized_value",
            format!("{label} did not exactly preserve the normalized value"),
            failures,
        ),
        Err(error) => failures.push(rpc_error("todo_expected_encode", error)),
    }
    match serde_json::from_value(value.clone()) {
        Ok(phases) => Some(phases),
        Err(error) => {
            failures.push(failure(
                "todo_strict_decode",
                format!("{label} was not a strict todo array: {error}"),
            ));
            None
        }
    }
}

fn task_status(phases: &[TodoPhase], content: &str) -> Option<TodoStatus> {
    phases
        .iter()
        .flat_map(|phase| phase.tasks.iter())
        .find(|task| task.content == content)
        .map(|task| task.status)
}
