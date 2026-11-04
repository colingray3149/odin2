//! Delegated-work reporting: the per-seat child-report pump that wakes a
//! conversation seat when its delegated work settles, enforces child
//! lifetimes and stall recovery, records gateway and lane fallbacks as
//! Huginn incidents, and releases finished pod runs' carrier Jobs.

use std::sync::Arc;

use crate::kube::KubeRuntimeCell;
use odin_domain::huginn::{LiveSessionId, OmpLivePlane};

pub(super) const CHILD_REPORT_TICK: std::time::Duration = std::time::Duration::from_secs(15);
/// Settles in a row with the same pending cause before the launching seat is told (five minutes).
const STUCK_SETTLES: u32 = 20;
/// Every this many child-report ticks (about a minute) the gateway's
/// per-session accounting is read for gateway fallbacks.
const FALLBACK_OBSERVE_TICKS: u64 = 4;
/// Children older than this are no longer reported on.
const CHILD_REPORT_WINDOW_MS: u64 = 24 * 3600 * 1000;
/// The bounded answer excerpt a delegated child's report wake carries.
/// Pod reports carry their whole settled answer instead.
const CHILD_REPORT_EXCERPT: usize = 2_000;

/// Report completion reads attribution through the same pod connections as its live tools.
pub(crate) fn bind_run_stats<P: OmpLivePlane + 'static>(
    runtime: Option<&Arc<odin_hermes::runtime::HermesRuntime>>,
    plane: Arc<P>,
    gateway: Option<String>,
    pods: Arc<odin_omp::host_tools::pod_exec::PodSessions>,
    exec: Arc<dyn odin_omp::host_tools::pod_exec::PodWorkerExec>,
) {
    if let Some(runtime) = runtime {
        runtime.set_run_stats_route(Arc::new(odin_hermes::runtime::DaemonRunStatsRoute {
            plane,
            gateway,
            pods,
            exec,
            handle: tokio::runtime::Handle::current(),
        }));
    }
}

/// Keep the whole answer because ending the pod session makes omitted text unretrievable.
/// `files` lists what the pod saved, already shared with this seat.
fn pod_report_text(pod: &odin_omp::host_tools::delegation::SettledPod, files: &str) -> String {
    if !pod.failed {
        format!(
            "A pod you launched finished its run. Its answer:\n{}\n{files}\
             Tell the owner what they need to know from it, plainly and with no ids.",
            pod.answer
        )
    } else {
        let said = if pod.answer.is_empty() {
            "It said nothing before failing.".to_owned()
        } else {
            format!("What it said before failing:\n{}", pod.answer)
        };
        let cause = pod.failure.as_ref().map_or(
            "Its journal names no cause for the failure.".to_owned(),
            |failure| format!("Why it failed ({}): {}", failure.code, failure.message),
        );
        format!(
            "A pod you launched stopped before finishing: its agent failed and \
             nothing took its work over, so its pod was released. {cause}\n{said}\n{files}\
             Tell the owner plainly what came of it and offer to run it again."
        )
    }
}

/// What the ask about a pod is called, the job its notes pin to, and the
/// profile that says which methods it had: the company its report is filed
/// under, else the run's label, else the pod's own session.
struct PodAsk {
    subject: String,
    job: String,
    profile: Option<String>,
}

fn pod_ask(
    connected: Option<&odin_huginn::kube::KubeControl>,
    pod: &odin_omp::host_tools::delegation::SettledPod,
) -> PodAsk {
    let session = pod.session.to_string();
    let launch = connected.and_then(|control| {
        control
            .reconciler()
            .operation_launch(&pod.operation)
            .unwrap_or_else(|error| {
                tracing::error!(
                    "pod launch unread operation={} reason={error}",
                    pod.operation
                );
                None
            })
    });
    let Some((run, launch)) = launch else {
        return PodAsk {
            subject: session.clone(),
            job: session,
            profile: None,
        };
    };
    PodAsk {
        subject: launch
            .workload
            .as_ref()
            .and_then(|plan| plan.company.clone())
            .or_else(|| launch.label.clone())
            .unwrap_or(session),
        job: run.as_str().to_owned(),
        profile: launch.workload.map(|plan| plan.profile),
    }
}

/// Queues a pod's wake. A pod that did not deliver its result (`unmet` names
/// what it left) keeps the ask about its subject open, with the methods it
/// called and the ones its profile offered that it did not; a delivered one
/// closes the ask.
async fn queue_pod_wake(
    runtime: &Arc<odin_hermes::runtime::HermesRuntime>,
    connected: Option<&odin_huginn::kube::KubeControl>,
    pod: &odin_omp::host_tools::delegation::SettledPod,
    wake_id: &str,
    text: &str,
    unmet: Option<Vec<String>>,
) -> Result<bool, String> {
    let ask = pod_ask(connected, pod);
    let Some(items) = unmet else {
        runtime.ask_delivered(&ask.subject)?;
        return runtime.wake_once(wake_id, text);
    };
    // The pump sees a stuck report again each tick; only the first needs the journal read.
    let methods = match ask
        .profile
        .clone()
        .filter(|_| !runtime.wake_queued(wake_id).unwrap_or(false))
    {
        Some(profile) => {
            let (runtime, session) = (Arc::clone(runtime), pod.session.to_string());
            tokio::task::spawn_blocking(move || runtime.pod_methods(&session, &profile))
                .await
                .map_err(|error| error.to_string())
                .and_then(|methods| methods)
                .map_err(|error| tracing::error!("pod methods unread: {error}"))
                .ok()
        }
        None => None,
    };
    runtime.report_unmet(
        wake_id,
        text,
        &odin_hermes::runtime::Unmet {
            subject: &ask.subject,
            job: &ask.job,
            items: &items,
            methods: methods
                .as_ref()
                .map(|(tried, untried)| (tried.as_slice(), untried.as_slice())),
        },
    )
}

/// Queues the wake of a delegated task that ended without its result: the ask
/// about the task stays open, with `unmet` as what it left.
fn queue_unmet_child(
    runtime: &odin_hermes::runtime::HermesRuntime,
    wake_id: &str,
    text: &str,
    task: &str,
    unmet: &str,
) -> Result<bool, String> {
    runtime.report_unmet(
        wake_id,
        text,
        &odin_hermes::runtime::Unmet {
            subject: task,
            job: task,
            items: &[unmet.to_owned()],
            methods: None,
        },
    )
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
             Tell the owner plainly what failed and what comes next — no ids."
        );
    }
    format!(
        "Work you delegated (task {child}) just finished a turn. Its answer:\n{excerpt}\n\
         Compare it with what you asked for. A turn result, completion prose, a pushed branch \
         or a merge receipt does not establish final task completion. If it stopped before \
         the task is done (a plan, a survey or a progress note instead of the result), tell it \
         to carry on with task_steer and say nothing to the owner. If it is asking you something, \
         answer it through task_steer or ask the owner. Keep incomplete work, questions and \
         escalations resumable; do not stop those children. Only after you accept the final \
         task result and no continuation or escalation remains, call \
         task_pause with childSession=\"{child}\" and action=\"stop\", and await success \
         before declaring that child stopped or cleaned up. If stop fails, report cleanup \
         as pending, not complete. If you lack task.pause authority, ask the authorized \
         owner to stop this exact child and do not claim cleanup. When the task is done or \
         truly blocked, tell the owner what they need to know — plainly, no ids. A successful \
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

/// How often the pump scans, and the declared child limits it enforces on that tick:
/// the hard time limit, the idle limit and the stall limit.
pub(super) struct PumpTiming {
    pub(super) every: std::time::Duration,
    pub(super) child_lifetime: Option<(
        std::time::Duration,
        Option<std::time::Duration>,
        Option<std::time::Duration>,
    )>,
}

/// Delegated work reports back unprompted: every settled turn of a child the
/// conversation seat delegated wakes that seat once, carrying the child's
/// answer, so the owner hears the result without asking.
pub(super) fn arm_child_report_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    runtime: Arc<odin_hermes::runtime::HermesRuntime>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    seat: odin_domain::SeatId,
    timing: PumpTiming,
    kube: Option<Arc<crate::kube::KubeRuntimeCell>>,
    desk: Arc<crate::incidents::IncidentDesk>,
) {
    let PumpTiming {
        every,
        child_lifetime,
    } = timing;
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tick: u64 = 0;
        // Retry durable pending releases until the carrier is stopped or gone.
        let mut pending: Vec<(LiveSessionId, String)> = Vec::new();
        // Each pod's last pending note and how many settles in a row repeated it.
        let mut repeated: std::collections::HashMap<String, (String, u32)> =
            std::collections::HashMap::new();
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
            let gateway = runtime.model_gateway();
            let settled = tokio::task::spawn_blocking(move || {
                // A working child that stalled is resumed (the Retry rung),
                // and ended once its retries are spent.
                let (mut stalled_out, mut switched, mut refused, mut timed_out) =
                    (Vec::new(), Vec::new(), Vec::new(), Vec::new());
                let mut resumed = Vec::new();
                if let Some(stall) = child_lifetime.and_then(|(_, _, stall)| stall) {
                    match scan.recover_stalled_children(stall) {
                        Ok(pass) => {
                            for failure in pass.failures {
                                tracing::error!("stalled delegated child not recovered: {failure}");
                            }
                            resumed = pass.resumed;
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
                    Some(Ok((retired, failures))) => {
                        timed_out = retired;
                        for failure in failures {
                            tracing::error!("delegated child limit scan: {failure}");
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
                if let (true, Some(gateway)) = (observe_fallbacks, gateway.as_deref()) {
                    let served = |child: &odin_domain::huginn::LiveSessionId, since_ms: u64| {
                        odin_hermes::runtime::read_tag_model_groups(
                            gateway,
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
                    (stalled_out, switched, refused, timed_out, rates, fallbacks),
                    resumed,
                ))
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            let (settled, pods, (stalled_out, switched, refused, timed_out, rates, fallbacks), _) =
                match settled {
                    Ok(settled) => {
                        for child in &settled.3 {
                            wake_declared(
                                &runtime,
                                "stall",
                                &format!("stall:{child}:resumed"),
                                &format!(
                                    "Task {child} stalled and was resumed by recovery; inspect its progress and steer it if needed."
                                ),
                            )
                            .await;
                        }
                        for switch in &settled.2.1 {
                            wake_declared(
                                &runtime,
                                "stall",
                                &format!("stall:{}:{}", switch.child, switch.to),
                                &format!(
                                    "Task {} moved from {} to {} after {}; it is still running.",
                                    switch.child,
                                    switch.from,
                                    switch.to,
                                    switch.cause.plain(),
                                ),
                            )
                            .await;
                        }
                        for out in &settled.2.0 {
                            wake_declared(
                                &runtime,
                                "stall",
                                &format!("stalled-{}", out.child),
                                &format!(
                                    "Work you are watching (task {}) stalled {} times and was stopped.",
                                    out.child,
                                    out.stalls.len()
                                ),
                            )
                            .await;
                        }
                        for child in &settled.0 {
                            wake_declared(
                                &runtime,
                                "child_report",
                                &odin_hermes::runtime::child_turn_wake_id(child.child, &child.key),
                                &settled_child_report(child),
                            )
                            .await;
                        }
                        settled
                    }
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
            // still start there, so the delegating seat tells the owner once,
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
                         Tell the owner in one plain sentence what happened and offer the \
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
                     was done. Tell the owner in one plain sentence what happened and offer an \
                     alternative (another declared model for that seat, or another seat). No \
                     ids.",
                    out.child,
                    out.lane,
                    out.cause.plain()
                );
                if let Err(error) = queue_unmet_child(
                    &runtime,
                    &format!("refused-{}", out.child),
                    &text,
                    &out.child.to_string(),
                    &format!("{} refused it: {}", out.lane, out.cause.plain()),
                ) {
                    tracing::error!("refused delegated work report not queued: {error}");
                }
            }
            for out in timed_out {
                let why = if out.idle {
                    "rested past its idle limit without finishing"
                } else {
                    "outlived its hard time limit"
                };
                tracing::warn!(
                    "delegated child ended by its lifetime child={} parent_seat={} idle={}",
                    out.child,
                    out.parent_seat.as_ref().map_or("", |seat| seat.as_str()),
                    out.idle
                );
                if out.parent_seat.as_ref() != Some(&seat) {
                    continue;
                }
                if let Some(finished) = out.finished {
                    if let Err(error) = runtime.ask_delivered(&out.child.to_string()) {
                        tracing::error!("open ask not closed: {error}");
                    }
                    let excerpt: String =
                        finished.answer.chars().take(CHILD_REPORT_EXCERPT).collect();
                    let text = format!(
                        "Work you delegated (task {}) finished; closed after idling. \
                         Its answer:\n{excerpt}\nTell the owner what came of it, plainly and with no ids.",
                        out.child,
                    );
                    if let Err(error) = runtime.wake_once(
                        &odin_hermes::runtime::child_turn_wake_id(out.child, &finished.key),
                        &text,
                    ) {
                        tracing::error!("finished idle delegated work report not queued: {error}");
                    }
                    continue;
                }
                let text = format!(
                    "Work you delegated (task {}) {why} and was stopped, so nothing more will \
                     come from it. Tell the owner in one plain sentence what was left undone, and \
                     delegate it again if they still want it (its pushed branch, if any, keeps \
                     its work). No ids.",
                    out.child
                );
                if let Err(error) = queue_unmet_child(
                    &runtime,
                    &format!("timed-out-{}", out.child),
                    &text,
                    &out.child.to_string(),
                    why,
                ) {
                    tracing::error!("timed-out delegated work report not queued: {error}");
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
                     tell the owner plainly. Worker lane stall record: {}",
                    out.child,
                    out.stalls.len(),
                    out.stalls.join(", "),
                    rates_line.as_deref().unwrap_or("unavailable")
                );
                if let Err(error) = queue_unmet_child(
                    &runtime,
                    &format!("stalled-{}", out.child),
                    &text,
                    &out.child.to_string(),
                    &format!("its model calls stalled {} times", out.stalls.len()),
                ) {
                    tracing::error!("stalled delegated work report not queued: {error}");
                }
            }
            for child in settled {
                let text = settled_child_report(&child);
                let wake_id = odin_hermes::runtime::child_turn_wake_id(child.child, &child.key);
                let task = child.child.to_string();
                let queued = if child.failed {
                    queue_unmet_child(
                        &runtime,
                        &wake_id,
                        &text,
                        &task,
                        "its latest turn failed before it finished the task",
                    )
                } else {
                    runtime
                        .ask_delivered(&task)
                        .and_then(|_| runtime.wake_once(&wake_id, &text))
                };
                if let Err(error) = queued {
                    tracing::error!("delegated work report not queued: {error}");
                }
            }
            // A pod run is one task. It is reported, ended and released only
            // after the report, the model's review of that exact render, and
            // durable laptop and Drive copies are done — or after its pod
            // was lost and the saved report was shared as artifacts instead.
            for pod in pods {
                let settlement = match (kube.as_ref(), connected.as_ref()) {
                    (Some(cell), Some(control)) => {
                        crate::report_settle::settle_pod_report(
                            cell, control, &runtime, &seat, &pod,
                        )
                        .await
                    }
                    _ => crate::report_settle::ReportSettlement::Pending {
                        note: "the cluster is not connected; the pod stays until its report can \
                               be settled"
                            .to_owned(),
                        follow_up: None,
                    },
                };
                match settlement {
                    crate::report_settle::ReportSettlement::Delivered { note, files } => {
                        PodFinish {
                            runtime: &runtime,
                            owner: &owner,
                            kube: kube.as_ref(),
                            connected: connected.as_deref(),
                            pending: &mut pending,
                        }
                        .finish(
                            &pod,
                            &format!("pod-{}-{}", pod.session, pod.key),
                            &pod_report_text(&pod, &format!("{note}\n{files}")),
                            pod.failed.then(|| {
                                vec![pod.failure.as_ref().map_or_else(
                                    || "the pod's agent failed and its journal names no cause".to_owned(),
                                    |failure| {
                                        format!(
                                            "the pod's agent failed ({}): {}",
                                            failure.code, failure.message
                                        )
                                    },
                                )]
                            }),
                            "delivered",
                        )
                        .await;
                    }
                    crate::report_settle::ReportSettlement::Salvaged { note, files } => {
                        PodFinish {
                            runtime: &runtime,
                            owner: &owner,
                            kube: kube.as_ref(),
                            connected: connected.as_deref(),
                            pending: &mut pending,
                        }
                        .finish(
                            &pod,
                            &format!("pod-salvaged-{}", pod.session),
                            &format!(
                                "A pod you launched lost its carrier before report delivery. \
                                 {note}\n{files}\nIts preserved answer (partial work):\n{}\n\
                                 Tell the owner what was recovered and what remains unfinished; \
                                 do not claim the PDF was reviewed or its copies delivered.",
                                pod.answer
                            ),
                            Some(vec![note]),
                            "salvaged",
                        )
                        .await;
                    }
                    crate::report_settle::ReportSettlement::Pending { note, follow_up } => {
                        let (last, count) = repeated
                            .entry(pod.operation.clone())
                            .or_insert_with(|| (String::new(), 0));
                        if follow_up.is_some() || *last != note {
                            (*last, *count) = (note.clone(), 0);
                        }
                        *count += 1;
                        // The same cause, settle after settle, will not clear on its own: the
                        // launching seat hears it once instead of the log repeating it.
                        if *count == STUCK_SETTLES {
                            let text = format!(
                                "A pod you launched cannot settle its report; the same cause \
                                 repeated for {} minutes: {note}\nTell the owner plainly what \
                                 is stuck. The pod stays up until its report is settled or it \
                                 is cancelled.",
                                (every * STUCK_SETTLES).as_secs() / 60
                            );
                            // One wake for what launched the pods, however many of them
                            // cannot settle for the same reason.
                            let launcher = pod_ask(connected.as_deref(), &pod).job;
                            let launcher = odin_domain::RunId::new(&launcher)
                                .ok()
                                .and_then(|run| crate::live::workload_watch::launching_session(&run))
                                .map_or(launcher, |session| session.to_string());
                            if let Err(error) = runtime.wake_event(
                                &format!("pod-report-stuck-{}", pod.operation),
                                &text,
                                &format!("pod-report:{launcher}"),
                                &odin_hermes::runtime::cause_of(&note),
                            ) {
                                tracing::error!("stuck report not queued: {error}");
                            }
                            tracing::error!(
                                "report settlement stuck session={} operation={} {note}",
                                pod.session, pod.operation
                            );
                        }
                        if let Some(turn) = follow_up {
                            let sending = Arc::clone(&owner);
                            let session = pod.session;
                            let started = tokio::task::spawn_blocking(move || {
                                sending.follow_up_with_images(session, &turn.text, &turn.images)
                            })
                            .await;
                            if let Err(error) = started.map_err(|error| error.to_string()).and_then(|result| result)
                            {
                                tracing::error!(
                                    "report review turn not started session={} {error}",
                                    pod.session
                                );
                            }
                        }
                        tracing::info!(
                            "report settlement pending session={} operation={} {note}",
                            pod.session, pod.operation
                        );
                    }
                    crate::report_settle::ReportSettlement::Failed { note } => {
                        let text = format!(
                            "A pod you launched has not delivered its report. {note}\n\
                             Tell the owner plainly what is missing. The pod stays up until the \
                             report, its review and both copies are done."
                        );
                        if let Err(error) = queue_pod_wake(
                            &runtime,
                            connected.as_deref(),
                            &pod,
                            &format!("pod-report-incomplete-{}", pod.session),
                            &text,
                            Some(vec![note.clone()]),
                        )
                        .await
                        {
                            tracing::error!("incomplete report not queued: {error}");
                        }
                        tracing::error!(
                            "report settlement failed session={} operation={} {note}",
                            pod.session, pod.operation
                        );
                    }
                }
            }
            if let Some(cell) = kube.as_ref().filter(|_| connected.is_some()) {
                drain_pending_pod_releases(cell, &mut pending).await;
            }
        }
    });
}

/// What ending one reported pod needs: the seat's wake route, the owner
/// that ends workload sessions, and the carrier-release queue with the
/// cluster connection that drains it.
struct PodFinish<'a> {
    runtime: &'a Arc<odin_hermes::runtime::HermesRuntime>,
    owner: &'a Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    kube: Option<&'a Arc<crate::kube::KubeRuntimeCell>>,
    connected: Option<&'a odin_huginn::kube::KubeControl>,
    pending: &'a mut Vec<(LiveSessionId, String)>,
}

impl PodFinish<'_> {
    /// Wake the launching seat that a pod run's report landed — delivered,
    /// or salvaged as artifacts after its carrier was lost — then end the
    /// workload session and release its carrier Job. A wake that cannot be
    /// queued leaves everything in place for the next pass; an
    /// unconfirmed release stays queued.
    async fn finish(
        self,
        pod: &odin_omp::host_tools::delegation::SettledPod,
        wake_id: &str,
        text: &str,
        unmet: Option<Vec<String>>,
        outcome: &str,
    ) {
        let Self {
            runtime,
            owner,
            kube,
            connected,
            pending,
        } = self;
        if pod.failed {
            let (code, detail) = pod.failure.as_ref().map_or(
                (
                    "unjournaled".to_owned(),
                    "no error event was journaled".to_owned(),
                ),
                |failure| (failure.code.clone(), failure.message.clone()),
            );
            tracing::error!(
                "pod session failed session={} operation={} said_chars={} \
                 failure_code={} failure_detail={}; releasing its pod",
                pod.session,
                pod.operation,
                pod.answer.chars().count(),
                code,
                detail,
            );
        }
        if let Err(error) = queue_pod_wake(runtime, connected, pod, wake_id, text, unmet).await {
            tracing::error!("pod report not queued: {error}");
            return;
        }
        tracing::info!(
            "pod report queued session={} operation={} answer_chars={} failed={} outcome={outcome}",
            pod.session,
            pod.operation,
            pod.answer.chars().count(),
            pod.failed
        );
        let session = pod.session;
        let ending = Arc::clone(owner);
        let ended = tokio::task::spawn_blocking(move || ending.end_workload(session))
            .await
            .map_err(|error| error.to_string());
        match ended {
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
        if let Some(control) = connected {
            let owed = match release_pod_job(control, &pod.operation).await {
                Ok(true) => None,
                Ok(false) => Some("its Job is not yet observed terminal".to_owned()),
                Err(error) => Some(error),
            };
            if let Some(error) = owed {
                tracing::error!("reported pod {session} job not released: {error}");
                if !pending.iter().any(|(_, queued)| queued == &pod.operation) {
                    pending.push((session, pod.operation.clone()));
                }
            }
        } else if kube.is_some() && !pending.iter().any(|(_, queued)| queued == &pod.operation) {
            pending.push((session, pod.operation.clone()));
        }
    }
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
    let admitted = reconciler
        .applied_observation(operation)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "release requires an applied launch observation".to_owned())?;
    if admitted.projection.labels.run_id != run
        || admitted.projection.identity.uid != observation.projection.identity.uid
    {
        return Err("release operation/run/Job UID no longer matches".to_owned());
    }
    if matches!(
        observation.workload.state,
        odin_domain::huginn::KubeWorkloadState::Succeeded
            | odin_domain::huginn::KubeWorkloadState::Failed
    ) {
        return Ok(true);
    }
    match odin_kube::exec::release_carrier(
        &reconciler.exec_client(),
        &run,
        admitted.projection.identity.uid.as_str(),
    )
    .await
    {
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
        .operate(odin_kube::JobAction {
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
    // No live session exists for admission refusals. Recover their durable
    // intents on every connected drain, including after daemon restart.
    let reconciler = control.reconciler();
    match reconciler.refused_releases() {
        Ok(operations) => {
            for operation in operations {
                match release_pod_job(&control, &operation).await {
                    Ok(true) => {
                        if let Err(error) = reconciler.complete_refused_release(&operation) {
                            tracing::error!(
                                "refused workload release acknowledgement failed: {error}"
                            );
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!("refused workload {operation} release pending: {error}")
                    }
                }
            }
        }
        Err(error) => tracing::error!("refused workload release inventory failed: {error}"),
    }
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

/// Prompts every enabled seat whose `[live] watches` names `watch`.
/// The conversation seat is woken by its own path; this is the declared
/// extra subscriber. The event id routes the wake: a `push:<project>` id
/// reaches that project's sessions, and an id that names a live session
/// reaches its parent when that parent is live. No owner text, so the wake
/// does not retire the seat. A refused wake is logged and left for the next
/// pass; the watcher's own delivery mark is not consumed here.
pub(crate) async fn wake_declared(
    runtime: &odin_hermes::runtime::HermesRuntime,
    watch: &str,
    id: &str,
    text: &str,
) {
    let Some(live) = odin_omp::live::service::OmpLiveService::installed() else {
        return;
    };
    let route = odin_omp::live::service::WakeRoute::from_event_id(id);
    for seat in runtime.seats_watching(watch) {
        if let Err(error) = live.wake_seat(&seat, id, text, route.as_ref()).await {
            tracing::error!("declared {watch} wake for {seat} failed: {error}");
        }
    }
}
