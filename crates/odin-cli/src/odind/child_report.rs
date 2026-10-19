//! Delegated-work reporting: the per-seat child-report pump that wakes a
//! conversation seat when its delegated work settles, enforces child
//! lifetimes and stall recovery, records gateway and lane fallbacks as
//! Huginn incidents, and releases finished pod runs' carrier Jobs.

use std::sync::Arc;

use crate::kube::KubeRuntimeCell;
use odin_domain::huginn::LiveSessionId;

const CHILD_REPORT_TICK: std::time::Duration = std::time::Duration::from_secs(15);
/// Every this many child-report ticks (about a minute) the gateway's
/// per-session accounting is read for gateway fallbacks.
const FALLBACK_OBSERVE_TICKS: u64 = 4;
/// Children older than this are no longer reported on.
const CHILD_REPORT_WINDOW_MS: u64 = 24 * 3600 * 1000;
/// The bounded answer excerpt a delegated child's report wake carries.
/// Pod reports carry their whole settled answer instead.
const CHILD_REPORT_EXCERPT: usize = 2_000;

/// Keep the whole answer because ending the pod session makes omitted text unretrievable.
fn pod_report_text(pod: &odin_omp::host_tools::delegation::SettledPod) -> String {
    if !pod.failed {
        format!(
            "A pod you launched finished its run. Its answer:\n{}\n\
             Tell Colin what he needs to know from it, plainly and with no ids.",
            pod.answer
        )
    } else {
        let said = if pod.answer.is_empty() {
            "It said nothing before failing.".to_owned()
        } else {
            format!("What it said before failing:\n{}", pod.answer)
        };
        format!(
            "A pod you launched stopped before finishing: its agent failed and \
             nothing took its work over, so its pod was released. {said}\n\
             Tell Colin plainly what came of it and offer to run it again."
        )
    }
}

/// A delegated child's report wake text. A failed turn is not successful
/// completion; its observed text is relayed as partial work only.
fn settled_child_report(settled: &odin_omp::host_tools::delegation::SettledChild) -> String {
    let child = settled.child;
    let excerpt: String = settled.answer.chars().take(CHILD_REPORT_EXCERPT).collect();
    if settled.failed {
        let said = if excerpt.is_empty() {
            "No partial work is available.".to_owned()
        } else {
            format!("The last text it wrote (partial work, not its result):\n{excerpt}")
        };
        return format!(
            "Work you delegated (task {child}) was observed failing its latest turn; this is not \
             successful task completion. {said}\n\
             Check its current task state first: it may already have recovered since this \
             report was captured. Do not present partial text as a final result. If it is \
             still failed and you choose to re-delegate, call task_pause with \
             childSession=\"{child}\" and action=\"stop\", and await success first. If stop \
             fails, report cleanup as pending. If you lack task.pause authority, ask an \
             authorized coordinator; do not claim cleanup or a completed learning review. \
             Tell Colin plainly what failed and what comes next — no ids."
        );
    }
    format!(
        "Work you delegated (task {child}) just finished a turn. Its answer:\n{excerpt}\n\
         Compare it with what you asked for. A turn result, completion prose, a pushed branch \
         or a merge receipt does not establish final task completion. If it stopped before \
         the task is done (a plan, a survey or a progress note instead of the result), tell it \
         to carry on with task_steer and say nothing to Colin. If it is asking you something, \
         answer it through task_steer or ask Colin. Keep incomplete work, questions and \
         escalations resumable; do not stop those children. Only after you accept the final \
         task result and no continuation or escalation remains, call \
         task_pause with childSession=\"{child}\" and action=\"stop\", and await success \
         before declaring that child stopped or cleaned up. If stop fails, report cleanup \
         as pending, not complete. If you lack task.pause authority, ask the authorized \
         owner to stop this exact child and do not claim cleanup. When the task is done or \
         truly blocked, tell Colin what he needs to know — plainly, no ids. A successful \
         stop proves teardown, not that task learning review has finished."
    )
}

/// One line of per-lane stall rates: `lane: stalls over workers (stalled)`.
fn lane_stall_line(
    rates: &std::collections::BTreeMap<String, odin_omp::host_tools::delegation::LaneStallRate>,
) -> String {
    rates
        .iter()
        .map(|(lane, rate)| {
            let mut line = format!(
                "{lane}: {} stalls over {} workers ({} stalled)",
                rate.stalls, rate.workers, rate.stalled_workers
            );
            if rate.fallback_workers > 0 {
                line.push_str(&format!(
                    ", {} requests of {} workers answered by a gateway fallback",
                    rate.fallback_requests, rate.fallback_workers
                ));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Delegated work reports back unprompted: every settled turn of a child the
/// conversation seat delegated wakes that seat once, carrying the child's
/// answer, so the owner hears the result without asking.
pub(super) fn arm_child_report_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    seat: odin_domain::SeatId,
    child_lifetime: Option<(
        std::time::Duration,
        Option<std::time::Duration>,
        Option<std::time::Duration>,
    )>,
    kube: Option<Arc<crate::kube::KubeRuntimeCell>>,
    desk: Arc<crate::incidents::IncidentDesk>,
) {
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(CHILD_REPORT_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tick: u64 = 0;
        // Retry durable pending releases until the carrier is stopped or gone.
        let mut pending: Vec<(LiveSessionId, String)> = Vec::new();
        let mut backlog_taken = false;
        loop {
            // A settled child is reported the moment its result is durable;
            // stall, lifetime and fallback scans stay on the tick.
            let timed = tokio::select! {
                _ = ticker.tick() => true,
                () = owner.result_wake().notified() => false,
            };
            if timed {
                tick = tick.wrapping_add(1);
            }
            let observe_fallbacks = timed && tick % FALLBACK_OBSERVE_TICKS == 1;
            let child_lifetime = child_lifetime.filter(|_| timed);
            let (scan, scan_seat) = (Arc::clone(&owner), seat.clone());
            let settled = tokio::task::spawn_blocking(move || {
                // A working child that stalled is resumed (the Retry rung),
                // and ended once its retries are spent.
                let (mut stalled_out, mut switched, mut refused) =
                    (Vec::new(), Vec::new(), Vec::new());
                if let Some(stall) = child_lifetime.and_then(|(_, _, stall)| stall) {
                    match scan.recover_stalled_children(stall) {
                        Ok(pass) => {
                            for failure in pass.failures {
                                tracing::error!("stalled delegated child not recovered: {failure}");
                            }
                            stalled_out = pass.ended;
                            switched = pass.switched;
                            refused = pass.refused;
                        }
                        Err(error) => {
                            tracing::error!("delegated child stall scan failed: {error}")
                        }
                    }
                }
                // The declared child lifetime is enforced here, in code:
                // a timed-out child is ended (its tab closes with it).
                match child_lifetime
                    .map(|(timeout, idle, _)| scan.retire_timed_out_children(timeout, idle))
                {
                    Some(Ok((_, failures))) => {
                        for failure in failures {
                            tracing::error!("timed-out delegated child not stopped: {failure}");
                        }
                    }
                    Some(Err(error)) => {
                        tracing::error!("delegated child timeout scan failed: {error}")
                    }
                    None => {}
                }
                // A gateway-configured fallback (LiteLLM answering a spent
                // lane from another model group with 200) never reaches the
                // worker as a refusal: read which lanes really served each
                // worker and put every fallback on its row.
                let mut fallbacks = Vec::new();
                if observe_fallbacks {
                    let served = |child: &odin_domain::huginn::LiveSessionId, since_ms: u64| {
                        odin_hermes::runtime::read_tag_model_groups(
                            &format!("{}{child}", odin_omp::SESSION_SPEND_TAG_PREFIX),
                            since_ms,
                        )
                    };
                    match scan.observe_gateway_fallbacks(&served) {
                        Ok((seen, failures)) => {
                            for failure in failures.iter().take(3) {
                                tracing::error!("gateway fallback read failed: {failure}");
                            }
                            for seen in &seen {
                                tracing::warn!(
                                    "delegated child served by gateway fallback child={} \
                                     lane={} served={} requests={} first={}",
                                    seen.child,
                                    seen.fallback.lane,
                                    seen.fallback.served,
                                    seen.fallback.requests,
                                    seen.first
                                );
                            }
                            fallbacks = seen;
                        }
                        Err(error) => tracing::error!("gateway fallback scan failed: {error}"),
                    }
                }
                // Every stall and fallback is reported with the lanes'
                // record so far.
                let first_fallback = fallbacks.iter().any(|seen| seen.first);
                let rates = if stalled_out.is_empty() && switched.is_empty() && !first_fallback {
                    None
                } else {
                    match scan.lane_stall_rates() {
                        Ok(rates) => Some(rates),
                        Err(error) => {
                            tracing::error!("lane stall rates unreadable: {error}");
                            None
                        }
                    }
                };
                let children = match scan.settled_children(&scan_seat, CHILD_REPORT_WINDOW_MS) {
                    Ok(children) => children,
                    Err(error) => {
                        tracing::error!("delegated child report scan failed: {error}");
                        Vec::new()
                    }
                };
                if let Err(error) =
                    scan.report_to_worker_parents(&scan_seat, CHILD_REPORT_WINDOW_MS)
                {
                    tracing::error!("delegated child report scan failed: {error}");
                }
                let pods = match scan.settled_workloads() {
                    Ok(pods) => pods,
                    Err(error) => {
                        tracing::error!("settled workload scan failed: {error}");
                        Vec::new()
                    }
                };
                Ok((
                    children,
                    pods,
                    (stalled_out, switched, refused, rates, fallbacks),
                ))
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            let (settled, pods, (stalled_out, switched, refused, rates, fallbacks)) = match settled
            {
                Ok(settled) => settled,
                Err(error) => {
                    tracing::error!("delegated work scan failed: {error}");
                    if let Some(cell) = kube.as_ref() {
                        if cell.connected_control().await.is_some() {
                            drain_pending_pod_releases(cell, &mut pending).await;
                        }
                    }
                    continue;
                }
            };
            // Releases wait until the cell is connected. Seeding or draining
            // before that logs a false "cluster is not reachable" per row.
            let connected = match kube.as_ref() {
                Some(cell) => cell.connected_control().await,
                None => None,
            };
            if let Some(control) = connected.as_ref().filter(|_| !backlog_taken) {
                let scanning = Arc::clone(&owner);
                let seeded =
                    tokio::task::spawn_blocking(move || scanning.ended_workload_sessions()).await;
                match seeded {
                    Ok(Ok(ended)) => match owed_ended_operations(control, &ended).await {
                        Ok(owed) => {
                            for (session, operation) in owed {
                                if pending.iter().any(|(_, queued)| queued == &operation) {
                                    continue;
                                }
                                pending.push((session, operation));
                            }
                            backlog_taken = true;
                        }
                        Err(error) => {
                            tracing::error!("pod release backlog scan failed: {error}");
                        }
                    },
                    Ok(Err(error)) => {
                        tracing::error!("pod release backlog scan failed: {error}");
                    }
                    Err(error) => {
                        tracing::error!("pod release backlog scan failed: {error}");
                    }
                }
            }
            let rates_line = rates.as_ref().map(lane_stall_line);
            if let Some(line) = &rates_line {
                tracing::debug!("lane stall rates {line}");
            }
            // A gateway fallback stays in Huginn too (an info incident): the
            // work goes on on the gateway's fallback lane.
            for seen in fallbacks.into_iter().filter(|seen| seen.first) {
                let desk = Arc::clone(&desk);
                let incident = crate::incidents::RaisedIncident {
                    source: format!(
                        "delegation:{}",
                        seen.parent_seat
                            .as_ref()
                            .map_or("unknown".to_owned(), |seat| seat.to_string())
                    ),
                    severity: odin_huginn::incidents::IncidentSeverityView::Info,
                    summary: format!(
                        "gateway fallback {} -> {}",
                        seen.fallback.lane, seen.fallback.served
                    ),
                    detail: format!(
                        "Delegated worker {} asked for {}, but the model gateway answered {} of \
                         its requests from its configured fallback {} (the lane refused them, \
                         e.g. a spent quota). Lane record: {}",
                        seen.child,
                        seen.fallback.lane,
                        seen.fallback.requests,
                        seen.fallback.served,
                        rates_line.as_deref().unwrap_or("unavailable")
                    ),
                    affected: vec![seen.child.to_string()],
                    signature: format!(
                        "gateway-fallback:{}:{}",
                        seen.fallback.lane, seen.fallback.served
                    ),
                };
                let _ = tokio::task::spawn_blocking(move || desk.raise(incident)).await;
            }
            // A lane fallback stays in Huginn (an info incident): the work
            // goes on, nobody needs to act — unless a provider refused the
            // lane (usage limit, rejected key): new work for the seat would
            // still start there, so the delegating seat tells Colin once,
            // with the alternative.
            for switch in switched {
                let desk = Arc::clone(&desk);
                let detail = if switch.cause.refuses_lane() {
                    format!(
                        "Delegated worker {} was refused on {} ({}) and its next request went to \
                         the seat's next declared launch option {}; it continues from where it \
                         was.",
                        switch.child,
                        switch.from,
                        switch.cause.plain(),
                        switch.to
                    )
                } else {
                    format!(
                        "Delegated worker {} stalled twice on {} and was moved to the seat's \
                         next declared launch option {}; it continues from where it was. Lane \
                         stall record: {}",
                        switch.child,
                        switch.from,
                        switch.to,
                        rates_line.as_deref().unwrap_or("unavailable")
                    )
                };
                if switch.cause.refuses_lane() && switch.parent_seat.as_ref() == Some(&seat) {
                    let text = format!(
                        "Work you delegated (task {}) was refused on {}: {}. Odin moved it to \
                         the seat's next declared model, {}, where it continues — nothing to \
                         redo. New work for that seat still starts on {} until it is switched. \
                         Tell Colin in one plain sentence what happened and offer the \
                         alternative: switching that seat to {} for new work. No ids.",
                        switch.child,
                        switch.from,
                        switch.cause.plain(),
                        switch.to,
                        switch.from,
                        switch.to
                    );
                    if let Err(error) = runtime
                        .wake_once(&format!("refused-{}-{}", switch.child, switch.from), &text)
                    {
                        tracing::error!("refused delegated work report not queued: {error}");
                    }
                }
                let incident = crate::incidents::RaisedIncident {
                    source: format!(
                        "delegation:{}",
                        switch
                            .parent_seat
                            .as_ref()
                            .map_or("unknown".to_owned(), |seat| seat.to_string())
                    ),
                    severity: odin_huginn::incidents::IncidentSeverityView::Info,
                    summary: format!("worker lane fallback {} -> {}", switch.from, switch.to),
                    detail,
                    affected: vec![switch.child.to_string()],
                    signature: format!("lane-fallback:{}:{}", switch.from, switch.to),
                };
                let _ = tokio::task::spawn_blocking(move || desk.raise(incident)).await;
            }
            for out in refused {
                if out.parent_seat.as_ref() != Some(&seat) {
                    continue;
                }
                let text = format!(
                    "Work you delegated (task {}) could not run: on {} {}, and its seat declares \
                     no other model that has not refused it, so it was stopped and nothing more \
                     was done. Tell Colin in one plain sentence what happened and offer an \
                     alternative (another declared model for that seat, or another seat). No \
                     ids.",
                    out.child,
                    out.lane,
                    out.cause.plain()
                );
                if let Err(error) = runtime.wake_once(&format!("refused-{}", out.child), &text) {
                    tracing::error!("refused delegated work report not queued: {error}");
                }
            }
            for out in stalled_out {
                if out.parent_seat.as_ref() != Some(&seat) {
                    continue;
                }
                let text = format!(
                    "Work you delegated (task {}) stalled {} times without progress (lanes: \
                     {}) — its model calls stopped answering — and was stopped. Delegate it \
                     again (its pushed branch, if any, keeps its work) or, if it keeps failing, \
                     tell Colin plainly. Worker lane stall record: {}",
                    out.child,
                    out.stalls.len(),
                    out.stalls.join(", "),
                    rates_line.as_deref().unwrap_or("unavailable")
                );
                if let Err(error) = runtime.wake_once(&format!("stalled-{}", out.child), &text) {
                    tracing::error!("stalled delegated work report not queued: {error}");
                }
            }
            for child in settled {
                let text = settled_child_report(&child);
                if let Err(error) =
                    runtime.wake_once(&format!("child-{}-{}", child.child, child.key), &text)
                {
                    tracing::error!("delegated work report not queued: {error}");
                }
            }
            // A pod run is one task: its settled turn (or its failure) is
            // reported once, its session is ended, and its carrier Job is
            // released.
            for pod in pods {
                let text = pod_report_text(&pod);
                if pod.failed {
                    tracing::error!(
                        "pod session failed session={} operation={} said_chars={}; \
                         releasing its pod",
                        pod.session,
                        pod.operation,
                        pod.answer.chars().count()
                    );
                }
                if let Err(error) =
                    runtime.wake_once(&format!("pod-{}-{}", pod.session, pod.key), &text)
                {
                    tracing::error!("pod report not queued: {error}");
                    continue;
                }
                tracing::error!(
                    "pod report queued session={} operation={} answer_chars={} failed={}",
                    pod.session,
                    pod.operation,
                    pod.answer.chars().count(),
                    pod.failed
                );
                let session = pod.session;
                let ending = Arc::clone(&owner);
                let ended = tokio::task::spawn_blocking(move || ending.end_workload(session))
                    .await
                    .map_err(|error| error.to_string());
                match ended {
                    // Settlement is durable; only the carrier release stays pending.
                    Ok(Ok(odin_omp::host_tools::delegation::ChildStop::SettledAbsent)) => {
                        tracing::info!(
                            "reported pod {session} settled absent: its end is \
                             journaled and never retried; only its job release stays pending"
                        );
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) | Err(error) => {
                        tracing::error!("reported pod {session} not ended: {error}");
                    }
                }
                if let Some(control) = connected.as_ref() {
                    let owed = match release_pod_job(control, &pod.operation).await {
                        Ok(true) => None,
                        Ok(false) => Some("its Job is not yet observed terminal".to_owned()),
                        Err(error) => Some(error),
                    };
                    if let Some(error) = owed {
                        tracing::error!("reported pod {session} job not released: {error}");
                        if !pending.iter().any(|(_, queued)| queued == &pod.operation) {
                            pending.push((session, pod.operation));
                        }
                    }
                } else if kube.is_some()
                    && !pending.iter().any(|(_, queued)| queued == &pod.operation)
                {
                    pending.push((session, pod.operation));
                }
            }
            if let Some(cell) = kube.as_ref().filter(|_| connected.is_some()) {
                drain_pending_pod_releases(cell, &mut pending).await;
            }
        }
    });
}

/// Ended sessions whose Job may still exist. One live inventory plus one
/// operation-to-run map; a gone or terminal Job is not owed.
async fn owed_ended_operations(
    control: &odin_huginn::kube::KubeControl,
    ended: &[(LiveSessionId, String)],
) -> Result<Vec<(LiveSessionId, String)>, String> {
    let reconciler = control.reconciler();
    let live = reconciler.list().await.map_err(|error| error.to_string())?;
    let open: std::collections::BTreeSet<_> = live
        .iter()
        .filter(|observation| {
            !matches!(
                observation.workload.state,
                odin_domain::huginn::KubeWorkloadState::Succeeded
                    | odin_domain::huginn::KubeWorkloadState::Failed
            )
        })
        .map(|observation| observation.projection.labels.run_id.clone())
        .collect();
    if open.is_empty() {
        return Ok(Vec::new());
    }
    let runs: std::collections::BTreeMap<_, _> = reconciler
        .operation_runs()
        .map_err(|error| error.to_string())?
        .into_iter()
        .collect();
    let mut owed = Vec::new();
    for (session, operation) in ended {
        if runs.get(operation).is_some_and(|run| open.contains(run)) {
            owed.push((*session, operation.clone()));
        }
    }
    Ok(owed)
}

/// Stop the parked carrier so a finished session's Job can complete.
/// `Ok(true)` means no launch, a missing or terminal Job, or a completed release;
/// `Ok(false)` keeps the release pending until terminal state is observed.
async fn release_pod_job(
    control: &odin_huginn::kube::KubeControl,
    operation: &str,
) -> Result<bool, String> {
    let reconciler = control.reconciler();
    let Some((run, _)) = reconciler
        .operation_launch(operation)
        .map_err(|error| error.to_string())?
    else {
        return Ok(true);
    };
    let Some(observation) = reconciler
        .observe_run(&run)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(true);
    };
    if matches!(
        observation.workload.state,
        odin_domain::huginn::KubeWorkloadState::Succeeded
            | odin_domain::huginn::KubeWorkloadState::Failed
    ) {
        return Ok(true);
    }
    match odin_kube::exec::release_carrier(&reconciler.exec_client(), &run).await {
        Ok(pod) => {
            tracing::info!(
                "pod run released run={run} pod={pod} carrier=stopped; its Job completes"
            );
            return Ok(true);
        }
        Err(error) => tracing::error!(
            "pod run release could not stop the carrier run={run}: {error}; cancelling \
             its Job instead"
        ),
    }
    let operation_id =
        odin_types::OperationId::new(&format!("op-{}", uuid::Uuid::new_v4().simple()))
            .map_err(|error| error.to_string())?;
    reconciler
        .operate_at_live_version(odin_kube::JobAction {
            idempotency_digest: odin_domain::Digest::hash(
                format!("pod-release:{}", run.as_str()).as_bytes(),
            ),
            run_id: run,
            kind: odin_domain::huginn::KubeOperationKind::Cancel,
            expected_resource_version: observation.projection.identity.resource_version,
            operation_id,
            target_node: None,
        })
        .await
        .map(|_| false)
        .map_err(|error| error.to_string())
}

/// Keep unconfirmed releases queued; log failures and wait silently while disconnected.
async fn drain_pending_pod_releases(
    cell: &KubeRuntimeCell,
    pending: &mut Vec<(LiveSessionId, String)>,
) {
    let Some(control) = cell.connected_control().await else {
        return;
    };
    let mut kept = Vec::new();
    for (session, operation) in pending.drain(..) {
        match release_pod_job(&control, &operation).await {
            Ok(true) => {}
            Ok(false) => kept.push((session, operation)),
            Err(error) => {
                tracing::error!("pending pod {session} release not confirmed: {error}");
                kept.push((session, operation));
            }
        }
    }
    *pending = kept;
}

#[cfg(test)]
#[path = "tests/child_report.rs"]
mod tests;
