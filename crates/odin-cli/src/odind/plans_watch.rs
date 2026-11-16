//! The seats' own plans, live: every open session whose plan holds a to-do is published as the
//! `Status` object `plans` (`odin view` shows it), and a to-do that turns blocked pages the owner
//! once through the incident desk.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use odin_huginn::incidents::IncidentSeverityView;
use odin_ledger::Ledger;
use serde_json::{json, Value};

use crate::incidents::{IncidentDesk, RaisedIncident};

/// How often the plans are read again: one small query, published only when they changed.
const PLANS_TICK: std::time::Duration = std::time::Duration::from_secs(10);

/// One open session's plan as the view shows it.
#[derive(Debug, PartialEq)]
struct SeatPlan {
    seat: String,
    session: String,
    objective: String,
    todos: Vec<(String, String, String)>,
}

/// The plans of the sessions still open, each with at least one to-do, by seat then session.
fn read_plans(ledger: &Ledger) -> Result<Vec<SeatPlan>, String> {
    let cause = |error: rusqlite::Error| format!("plans read: {error}");
    let mut statement = ledger
        .connection()
        .prepare(
            "SELECT s.seat_id, s.session_id, p.objective, i.item_id, i.title, i.status
             FROM live_sessions s
             JOIN plans p ON p.run_id = 'run:live:' || s.session_id
             JOIN plan_items i ON i.run_id = p.run_id
             WHERE s.state NOT IN ('ended', 'failed') AND s.retired_at IS NULL
             ORDER BY s.seat_id, s.session_id, i.ordinal",
        )
        .map_err(cause)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                (row.get(3)?, row.get(4)?, row.get(5)?),
            ))
        })
        .map_err(cause)?;
    let mut plans: Vec<SeatPlan> = Vec::new();
    for row in rows {
        let (seat, session, objective, todo) = row.map_err(cause)?;
        match plans.last_mut() {
            Some(plan) if plan.session == session => plan.todos.push(todo),
            _ => plans.push(SeatPlan {
                seat,
                session,
                objective,
                todos: vec![todo],
            }),
        }
    }
    Ok(plans)
}

fn plans_value(plans: &[SeatPlan]) -> Value {
    json!({"plans": plans.iter().map(|plan| json!({
        "seat": plan.seat,
        "session": plan.session,
        "objective": plan.objective,
        "todos": plan.todos.iter().map(|(id, title, status)| json!({"id": id, "title": title, "status": status})).collect::<Vec<_>>(),
    })).collect::<Vec<_>>()})
}

/// The blocked to-dos, keyed by session and to-do id.
fn blocked(plans: &[SeatPlan]) -> BTreeSet<(String, String)> {
    plans
        .iter()
        .flat_map(|plan| {
            plan.todos
                .iter()
                .filter(|(_, _, status)| status == "blocked")
                .map(|(id, _, _)| (plan.session.clone(), id.clone()))
        })
        .collect()
}

/// The incident for a to-do that turned blocked since the last read.
fn blocked_incident(plan: &SeatPlan, id: &str, title: &str) -> RaisedIncident {
    let mut seat = plan.seat.clone();
    if let Some(first) = seat.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    RaisedIncident {
        source: format!("seat:{}", plan.seat),
        // Error pages the phone: a blocked seat waits on the owner.
        severity: IncidentSeverityView::Error,
        summary: format!("{seat} is blocked: {title}"),
        detail: format!(
            "A to-do in {seat}'s plan went blocked. Its objective: {}",
            plan.objective
        ),
        affected: vec![plan.session.clone()],
        signature: format!("todo-blocked:{}:{id}", plan.session),
    }
}

/// Arms the plans pump on the authority, where the ledger holds the seats' plans.
pub(crate) fn arm_plans_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: odin_huginn::NodePosture,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    ledger: Arc<Mutex<Ledger>>,
    desk: Arc<IncidentDesk>,
) {
    if posture == odin_huginn::NodePosture::Follower {
        return;
    }
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(PLANS_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // What was blocked at the last read; the first read only learns it, so a restart pages nobody.
        let mut known: Option<BTreeSet<(String, String)>> = None;
        loop {
            ticker.tick().await;
            let plans = {
                let ledger = ledger
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                read_plans(&ledger)
            };
            let plans = match plans {
                Ok(plans) => plans,
                Err(error) => {
                    tracing::error!("{error}");
                    continue;
                }
            };
            if let Err(error) = crate::huginn_spend::publish_status(
                &read_model,
                crate::huginn_spend::status_object("plans"),
                plans_value(&plans),
                time::OffsetDateTime::now_utc(),
            ) {
                tracing::error!("plans publication failed: {error}");
            }
            let now_blocked = blocked(&plans);
            if let Some(before) = &known {
                for plan in &plans {
                    for (id, title, status) in &plan.todos {
                        if status == "blocked"
                            && !before.contains(&(plan.session.clone(), id.clone()))
                        {
                            desk.raise(blocked_incident(plan, id, title));
                        }
                    }
                }
            }
            known = Some(now_blocked);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(statuses: &[&str]) -> SeatPlan {
        SeatPlan {
            seat: "gungnir".into(),
            session: "s1".into(),
            objective: "ship it".into(),
            todos: statuses
                .iter()
                .enumerate()
                .map(|(n, status)| (format!("t{n}"), format!("step {n}"), (*status).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn the_view_gets_each_seats_objective_and_todos_and_a_block_names_the_seat() {
        let plans = [plan(&["completed", "blocked"])];
        let value = plans_value(&plans);
        assert_eq!(value["plans"][0]["seat"], "gungnir");
        assert_eq!(value["plans"][0]["todos"][1]["status"], "blocked");
        assert_eq!(
            blocked(&plans),
            BTreeSet::from([("s1".to_owned(), "t1".to_owned())])
        );
        let incident = blocked_incident(&plans[0], "t1", "step 1");
        assert_eq!(incident.summary, "Gungnir is blocked: step 1");
        assert_eq!(incident.signature, "todo-blocked:s1:t1");
        assert_eq!(incident.severity, IncidentSeverityView::Error);
    }

    #[test]
    fn plans_of_open_sessions_are_read_in_order() {
        let ledger = Ledger::open_in_memory().unwrap();
        ledger
            .connection()
            .execute_batch(
                "INSERT INTO lanes(lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at)
                 VALUES ('lane:x', 'seat:gungnir', 't', 'local_omp', 'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');
                 INSERT INTO runs(run_id, lane_id, attempt_number, status, input_hash, created_at, updated_at)
                 VALUES ('run:live:s1', 'lane:x', 1, 'pending', 'h', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');",
            )
            .unwrap();
        let session = |state: &str| {
            format!(
                "INSERT INTO live_sessions(session_id, seat_id, project_id, slice_id, lane_id, target_node_id,
                 provider, model, open_tab, state, created_at, updated_at)
                 VALUES ('s1', 'gungnir', 'odin', 'x', 'lane:x', 'mini', 'gateway', 'm', 0, '{state}',
                 '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');"
            )
        };
        ledger
            .connection()
            .execute_batch(&session("ready"))
            .unwrap();
        let mut ledger = ledger;
        ledger
            .replace_plan(
                &"run:live:s1".parse().unwrap(),
                "ship it",
                &[
                    odin_ledger::plan::TodoSpec {
                        id: "a".parse().unwrap(),
                        title: "first".into(),
                        status: odin_ledger::plan::TodoStatus::Completed,
                    },
                    odin_ledger::plan::TodoSpec {
                        id: "b".parse().unwrap(),
                        title: "second".into(),
                        status: odin_ledger::plan::TodoStatus::Blocked,
                    },
                ],
                0,
                time::OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        let plans = read_plans(&ledger).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].todos[1],
            ("b".into(), "second".into(), "blocked".into())
        );
    }
}
