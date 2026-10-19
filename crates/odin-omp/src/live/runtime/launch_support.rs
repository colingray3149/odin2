use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    EventSeq, HistoryQuery, LiveError, LiveEventBody, SessionManifest, TerminalSeq,
};
use odin_domain::{Digest, LaneId, ProjectId, RunId, SeatId, SessionId};
use odin_ledger::lane_run::{self, NewLane, NewRun};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use crate::host_tools::delegation::DelegationLinkLedger;
use crate::live::ledger::LiveLedger;

use super::errors::{conflict, invalid, unavailable};

/// The ledger lane row a live session of `seat` on `project` runs under.
/// Declared lanes are materialized in this exact shape before any session
/// opens, so embedding leases and backfills never meet a missing lane.
pub fn live_session_lane(lane_id: LaneId, seat_id: SeatId, project_id: ProjectId) -> NewLane {
    NewLane {
        lane_id,
        seat_id,
        project_id: Some(project_id),
        template_id: "default".to_owned(),
        backend: "local_omp".to_owned(),
        created_by: "live-session".to_owned(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        retained: false,
    }
}

/// Objective and single todo of a pod agent's plan: the pod's declared
/// brief is its work, accepted when the launching session's accepted plan
/// launched it.
pub(super) const POD_PLAN_OBJECTIVE: &str = "Execute the pod's declared brief";
const POD_PLAN_TODO_ID: &str = "todo:pod-brief";
const POD_PLAN_TODO_TITLE: &str = "Execute the declared brief to completion";

/// Gives a pod agent's run the plan a delegated child gets: one plan, its
/// acceptance inherited from the run of the session that launched the pod.
/// Without it every side-effecting pod tool is refused `NeedsPlan`, and a
/// pod has no plan tool. Idempotent on reopen. A launcher with no accepted
/// plan leaves the pod without one (the kernel then refuses side effects,
/// typed); `Ok(false)` says so.
pub(super) async fn ensure_pod_plan(
    bridge_ledger: &Arc<Mutex<Ledger>>,
    run_id: &RunId,
    launching_run: &str,
) -> Result<bool, LiveError> {
    let ledger = Arc::clone(bridge_ledger);
    let run_id = run_id.clone();
    let launching = RunId::new(launching_run)
        .map_err(|_| invalid("the pod's launching run is not a run identity"))?;
    tokio::task::spawn_blocking(move || -> Result<bool, LiveError> {
        let mut guard = ledger
            .lock()
            .map_err(|_| unavailable("bridge_ledger_lock"))?;
        let ledger_error = |error: odin_ledger::LedgerError| {
            unavailable(&format!("bridge_ledger_pod_plan: {error}"))
        };
        if guard.plan_is_accepted(&run_id).map_err(ledger_error)? {
            return Ok(true);
        }
        if !guard.plan_is_accepted(&launching).map_err(ledger_error)? {
            return Ok(false);
        }
        let observed = guard
            .plan(&run_id)
            .map_err(ledger_error)?
            .map_or(0, |plan| plan.revision);
        guard
            .replace_plan(
                &run_id,
                POD_PLAN_OBJECTIVE,
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new(POD_PLAN_TODO_ID)
                        .map_err(|error| invalid(error.to_string()))?,
                    title: POD_PLAN_TODO_TITLE.to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                observed,
                OffsetDateTime::now_utc(),
            )
            .map_err(ledger_error)?;
        guard
            .inherit_plan_acceptance(&launching, &run_id, OffsetDateTime::now_utc())
            .map_err(ledger_error)?;
        Ok(true)
    })
    .await
    .map_err(|_| unavailable("bridge_ledger_pod_plan_task"))?
}

pub(super) async fn ensure_bridge_run(
    bridge_ledger: &Arc<Mutex<Ledger>>,
    run_id: &RunId,
    lane_id: &LaneId,
    manifest: &SessionManifest,
) -> Result<(), LiveError> {
    let ledger = Arc::clone(bridge_ledger);
    let run_id = run_id.clone();
    let lane_id = lane_id.clone();
    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|_| invalid("session manifest is not serializable"))?;
    let input_hash = Digest::hash(&manifest_bytes).to_string();
    let workflow_id = Some(format!("live:{}", manifest.slice_id));
    let seat_id = manifest.seat_id.clone();
    let project_id = manifest.project_id.clone();
    tokio::task::spawn_blocking(move || -> Result<(), LiveError> {
        let guard = ledger
            .lock()
            .map_err(|_| unavailable("bridge_ledger_lock"))?;
        let conn = guard.connection();
        lane_run::ensure_lane(
            conn,
            &live_session_lane(lane_id.clone(), seat_id, project_id),
        )
        .map_err(|error| unavailable(&format!("bridge_ledger_lane ensure: {error}")))?;
        if let Some(existing) = lane_run::read_run(conn, &run_id)
            .map_err(|error| unavailable(&format!("bridge_ledger_run read: {error}")))?
        {
            if existing.lane_id != lane_id {
                return Err(conflict(
                    "live session run is already bound to a different lane",
                ));
            }
            return Ok(());
        }
        let attempt_number: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM runs WHERE lane_id = ?1",
                [lane_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| unavailable(&format!("bridge_ledger_run query: {error}")))?;
        let new_run = NewRun {
            run_id,
            lane_id,
            attempt_number,
            workflow_id,
            workflow_version: Some(1),
            input_hash,
            accepted_capability_revision: None,
            lease_id: None,
            absolute_deadline: None,
            retry_budget: 0,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        lane_run::create_run(conn, &new_run)
            .map_err(|error| unavailable(&format!("bridge_ledger_run create: {error}")))?;
        Ok(())
    })
    .await
    .map_err(|_| unavailable("bridge_ledger_task"))?
}
pub(super) async fn terminal_head(
    ledger: &dyn LiveLedger,
    session_id: odin_domain::huginn::LiveSessionId,
) -> Result<TerminalSeq, LiveError> {
    let mut after = EventSeq::new(0);
    let mut terminal = TerminalSeq::new(0);
    let limit = NonZeroU16::new(1024).ok_or_else(|| unavailable("terminal_history_limit"))?;
    loop {
        let page = ledger
            .history(HistoryQuery {
                session_id,
                after,
                limit,
            })
            .await
            .map_err(|_| unavailable("terminal_history"))?;
        for event in &page.events {
            let candidate = match &event.body {
                LiveEventBody::TerminalSnapshot(snapshot) => Some(snapshot.sequence),
                LiveEventBody::TerminalDelta(delta) => Some(delta.sequence),
                _ => None,
            };
            if let Some(candidate) = candidate {
                terminal = terminal.max(candidate);
            }
        }
        if page.next_after >= page.head || page.events.is_empty() {
            return Ok(terminal);
        }
        after = page.next_after;
    }
}

/// Production delegated-child state source for the rollover brief: the
/// durable delegation-link rows joined with the live ledger's current child
/// session projections, bounded by the caller's cap. Read-only; the bridge
/// consumes it only while rendering a rollover brief.
pub(super) struct BridgeRolloverChildren {
    pub(super) links: DelegationLinkLedger,
    pub(super) live: Arc<dyn LiveLedger>,
}

#[async_trait]
impl crate::live::rollover::RolloverChildrenSource for BridgeRolloverChildren {
    async fn children(
        &self,
        parent: &SessionId,
        cap: usize,
    ) -> Result<Vec<crate::live::rollover::RolloverChildState>, String> {
        let links = self.links.clone();
        let parent = parent.clone();
        let mut rows = tokio::task::spawn_blocking(move || links.children_of(&parent))
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| format!("delegation link listing failed: {error}"))?;
        if rows.len() > cap {
            let drop = rows.len() - cap;
            rows.drain(..drop);
        }
        let mut children = Vec::with_capacity(rows.len());
        for row in rows {
            let projection = self.live.session(row.child).await.ok();
            children.push(crate::live::rollover::RolloverChildState {
                child_session: row.child.to_string(),
                phase: serde_json::to_value(row.phase)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "unknown".to_owned()),
                project: row.project.to_string(),
                provider: row.provider,
                model: row.model,
                depth: row.depth,
                prompt_digest: row.prompt_digest.to_string(),
                created_at_ms: row.created_at_ms,
                epoch: projection
                    .as_ref()
                    .and_then(|session| serde_json::to_value(session.epoch).ok())
                    .map(|value| value.to_string()),
                event_head: projection
                    .as_ref()
                    .and_then(|session| serde_json::to_value(session.head).ok())
                    .map(|value| value.to_string()),
            });
        }
        Ok(children)
    }

    /// The session's own delegated assignment, when it is a delegated
    /// child: the exact prompt text persisted on its link row at
    /// admission, carried verbatim into the rollover brief independent of
    /// every evictable conversation tail. A session that is nobody's
    /// delegated child reads `Ok(None)`. A delegated child whose row
    /// predates the field is a typed refusal — its rollover cannot
    /// honestly continue the task, never a generic absorb.
    async fn assignment(&self, session: &SessionId) -> Result<Option<String>, String> {
        let child = crate::host_tools::delegation::live_session_id(session)
            .map_err(|error| format!("session {session} is not a live child id: {error}"))?;
        let links = self.links.clone();
        let row = tokio::task::spawn_blocking(move || links.load(&child))
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| format!("delegation link read failed: {error}"))?;
        match row {
            None => Ok(None),
            Some(row) if row.assignment.is_empty() => Err(format!(
                "delegated child {child} has a durable row without its assignment (a legacy \
                 row): the rollover cannot honestly continue the task"
            )),
            Some(row) => Ok(Some(row.assignment)),
        }
    }
}

#[cfg(test)]
mod pod_plan_tests {
    use super::*;

    fn run(ledger: &Ledger, lane: &LaneId, id: &str, attempt: i64) -> RunId {
        let run_id = RunId::new(id).unwrap();
        lane_run::create_run(
            ledger.connection(),
            &NewRun {
                run_id: run_id.clone(),
                lane_id: lane.clone(),
                attempt_number: attempt,
                workflow_id: None,
                workflow_version: None,
                input_hash: "fixture".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
        .unwrap();
        run_id
    }

    #[tokio::test]
    async fn a_pod_run_inherits_its_launching_runs_accepted_plan() {
        let ledger = Ledger::open_in_memory().unwrap();
        let lane = LaneId::new("kubert-odin").unwrap();
        lane_run::create_lane(
            ledger.connection(),
            &NewLane {
                lane_id: lane.clone(),
                seat_id: SeatId::new("kubert").unwrap(),
                project_id: None,
                template_id: "template:dev".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                retained: false,
            },
        )
        .unwrap();
        let launcher = run(&ledger, &lane, "run:live:launcher", 1);
        let pod = run(&ledger, &lane, "run:live:pod-agent", 2);
        let ledger = Arc::new(Mutex::new(ledger));

        // A launcher without an accepted plan gives the pod none.
        assert!(!ensure_pod_plan(&ledger, &pod, launcher.as_str())
            .await
            .unwrap());
        assert!(!ledger.lock().unwrap().plan_is_accepted(&pod).unwrap());

        {
            let mut guard = ledger.lock().unwrap();
            let plan = guard
                .replace_plan(
                    &launcher,
                    "Launch the probe",
                    &[odin_ledger::plan::TodoSpec {
                        id: odin_domain::TodoId::new("todo:launch").unwrap(),
                        title: "Launch".to_owned(),
                        status: odin_ledger::plan::TodoStatus::Pending,
                    }],
                    0,
                    OffsetDateTime::UNIX_EPOCH,
                )
                .unwrap();
            guard
                .accept_plan(
                    &launcher,
                    plan.revision,
                    "operator:fixture",
                    OffsetDateTime::UNIX_EPOCH,
                )
                .unwrap();
        }
        assert!(ensure_pod_plan(&ledger, &pod, launcher.as_str())
            .await
            .unwrap());
        {
            let guard = ledger.lock().unwrap();
            assert!(guard.plan_is_accepted(&pod).unwrap());
            assert_eq!(
                guard.plan(&pod).unwrap().unwrap().objective,
                POD_PLAN_OBJECTIVE
            );
        }
        // Reopen is idempotent.
        assert!(ensure_pod_plan(&ledger, &pod, launcher.as_str())
            .await
            .unwrap());
    }

    /// The assignment source distinguishes the three standings a session
    /// can have: a delegated child with its verbatim admitted assignment,
    /// a session that is nobody's delegated child, and a legacy delegated
    /// row whose missing assignment is a TYPED refusal — a worker's
    /// rollover never silently degrades to a generic absorb without the
    /// requirements.
    #[tokio::test]
    async fn the_assignment_source_distinguishes_delegated_legacy_and_free_sessions() {
        use crate::live::rollover::RolloverChildrenSource;
        use odin_domain::huginn::LiveSessionId;
        use odin_domain::CommandId;

        let root = tempfile::tempdir().unwrap();
        let links =
            DelegationLinkLedger::open(root.path().join("links")).expect("delegation ledger");
        let live = Arc::new(
            crate::live::ledger::fs::FsLiveLedger::open(root.path().join("live")).unwrap(),
        ) as Arc<dyn LiveLedger>;
        let source = BridgeRolloverChildren {
            links: links.clone(),
            live,
        };
        let child_of = |name: &str| {
            crate::live::supervisor::session_id_for(
                &CommandId::new(format!("odin.task.create:assignment-{name}")).unwrap(),
            )
            .unwrap()
        };
        let row = |child: LiveSessionId, assignment: &str| {
            crate::host_tools::delegation::DelegationLink {
                schema: crate::host_tools::delegation::DELEGATION_LINK_SCHEMA.to_owned(),
                child,
                parent: SessionId::new("00000000-0000-4000-8000-0000000000a1").unwrap(),
                parent_seat: Some(SeatId::new("seat.architect").unwrap()),
                parent_run: RunId::new("run:live:00000000-0000-4000-8000-0000000000a0").unwrap(),
                child_run: crate::host_tools::delegation::GovernedTaskOwner::child_run_for(&child)
                    .unwrap(),
                command: CommandId::new(format!("odin.task.create:assignment-{}", child)).unwrap(),
                project: ProjectId::new("project.odin").unwrap(),
                provider: "gateway".to_owned(),
                model: "glm-flash".to_owned(),
                prompt_digest: Digest::hash(b"prompt"),
                depth: 1,
                phase: crate::host_tools::delegation::DelegationPhase::Running,
                created_at_ms: 1,
                learning_capture_sequence: None,
                escalated_to: None,
                escalation_open: false,
                learning_result_sequence: None,
                learning_proposal_id: None,
                stall_retries: 0,
                stalls: Vec::new(),
                switched_to: None,
                handled_stall_event: None,
                refusals: Vec::new(),
                gateway_fallbacks: Vec::new(),
                reported_answer: None,
                pending_report: None,
                assignment: assignment.to_owned(),
                rollover_admissions: 0,
            }
        };
        let session = |child: &LiveSessionId| SessionId::new(child.to_string()).unwrap();
        let legacy = child_of("legacy");
        links.persist(&row(legacy, "")).unwrap();
        let current = child_of("current");
        links
            .persist(&row(current, "the admitted assignment text"))
            .unwrap();
        let refusal = source.assignment(&session(&legacy)).await.unwrap_err();
        assert!(
            refusal.contains("legacy row"),
            "a legacy delegated row refuses typed: {refusal}"
        );
        assert_eq!(
            source.assignment(&session(&current)).await.unwrap(),
            Some("the admitted assignment text".to_owned())
        );
        assert_eq!(
            source
                .assignment(&session(&child_of("free")))
                .await
                .unwrap(),
            None,
            "a session that is nobody's delegated child has no assignment"
        );
    }
}
