//! Child recovery, lifecycle reconciliation, and parent-stop coordination.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use odin_domain::huginn::LiveSessionId;
use odin_domain::SessionId;

use super::contracts::{
    ChildLifecycleSnapshot, ChildStopCoordinator, ChildStopRecord, ProviderFaultKind,
    ProviderFaultOrigin, ProviderTurnFault,
};
use super::links::{DelegationLink, DelegationPhase, GatewayFallback, LaneRefusal, WorkerLane};
use super::owner::GovernedTaskOwner;
use super::vocabulary::TaskToolFailure;

/// Stalled turns of one delegated child the kernel cancels and resumes
/// before it ends the child instead.
pub const MAX_STALL_RETRIES: u8 = 2;
/// Rollovers per task, counted before respawn; failed starts consume the durable budget too.
pub const MAX_ROLLOVER_ADMISSIONS: u8 = 2;

#[derive(Debug, Default)]
pub struct StallPass {
    pub resumed: Vec<LiveSessionId>,
    pub switched: Vec<LaneSwitch>,
    pub ended: Vec<StalledOut>,
    pub refused: Vec<RefusedOut>,
    pub failures: Vec<String>,
}

/// A child moved to its seat's next declared lane: after a repeated stall,
/// or at its next request after a provider refused one (`cause`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneSwitch {
    pub child: LiveSessionId,
    pub parent_seat: Option<odin_domain::SeatId>,
    pub from: WorkerLane,
    pub to: WorkerLane,
    pub cause: ProviderFaultKind,
}

/// A child ended because its provider refused its request and its seat
/// declares no other lane it has not been refused on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefusedOut {
    pub child: LiveSessionId,
    pub parent_seat: Option<odin_domain::SeatId>,
    pub lane: WorkerLane,
    pub cause: ProviderFaultKind,
}

/// A gateway fallback the kernel newly saw (or saw grow) for one worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackSeen {
    pub child: LiveSessionId,
    pub parent_seat: Option<odin_domain::SeatId>,
    pub fallback: GatewayFallback,
    /// `true` the first time this served lane is seen for the worker.
    pub first: bool,
}

/// How long after its creation a finished worker's gateway accounting is
/// still read: the gateway aggregates per-session counts about once a
/// minute, so a short task's last requests land after it settled.
pub const FALLBACK_OBSERVE_WINDOW_MS: u64 = 2 * 60 * 60 * 1000;

/// Reads the gateway model groups (group -> requests) that answered one
/// worker's requests since a time in milliseconds.
pub type GatewayServedReader<'a> =
    dyn Fn(&LiveSessionId, u64) -> Result<BTreeMap<String, u64>, String> + 'a;

/// The worker's gateway fallbacks after one read of the gateway's
/// per-session accounting (`served`: model group -> requests answered).
/// A model group that is none of the worker's gateway lanes answered
/// requests the worker addressed to its own lane: it is recorded against
/// the lane the worker ran on when the fallback was first seen, and its
/// count follows the gateway's.
pub fn gateway_fallbacks_seen(
    link: &DelegationLink,
    served: &BTreeMap<String, u64>,
    gateway_provider: &str,
) -> Vec<GatewayFallback> {
    let own: BTreeSet<String> = link
        .lanes()
        .into_iter()
        .filter(|lane| lane.provider == gateway_provider)
        .map(|lane| lane.model)
        .collect();
    let mut fallbacks = link.gateway_fallbacks.clone();
    for (group, requests) in served {
        if *requests == 0 || own.contains(group) {
            continue;
        }
        match fallbacks.iter_mut().find(|seen| &seen.served == group) {
            Some(seen) => seen.requests = seen.requests.max(*requests),
            None => fallbacks.push(GatewayFallback {
                lane: link.current_lane().to_string(),
                served: group.clone(),
                requests: *requests,
            }),
        }
    }
    fallbacks
}

/// A child ended after its stall budget, with every lane it stalled on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StalledOut {
    pub child: LiveSessionId,
    pub parent_seat: Option<odin_domain::SeatId>,
    pub stalls: Vec<String>,
}

/// One lane's stall record over the delegation rows the ledger holds.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneStallRate {
    /// Workers that ran on the lane (launched on it or switched to it).
    pub workers: u32,
    /// Of those, workers that stalled on it at least once.
    pub stalled_workers: u32,
    pub stalls: u32,
    /// Workers whose requests to the lane the gateway answered from another
    /// lane (a gateway-configured fallback).
    pub fallback_workers: u32,
    /// Requests to the lane the gateway answered from another lane.
    pub fallback_requests: u64,
}

/// Next distinct lane in declaration order, wrapping once to preserve seat preference.
pub fn next_declared_lane(options: &[WorkerLane], current: &WorkerLane) -> Option<WorkerLane> {
    let start = options
        .iter()
        .position(|option| option == current)
        .map_or(0, |index| index + 1);
    options[start..]
        .iter()
        .chain(&options[..start])
        .find(|option| *option != current)
        .cloned()
}

/// The fallback a stalled OMP worker can really take: a lane switch is a
/// live OMP `SetModel`, so only the seat's OMP launch options (no
/// `harness`) are candidates — a harness option is a
/// different program, not a model of this session. A worker whose own lane
/// is declared only as a harness option has no OMP fallback.
pub fn next_switchable_lane(
    options: &[odin_domain::huginn::LiveLaunchOption],
    current: &WorkerLane,
) -> Option<WorkerLane> {
    let lane = |option: &odin_domain::huginn::LiveLaunchOption| WorkerLane {
        provider: option.provider.to_string(),
        model: option.model.to_string(),
    };
    let omp: Vec<WorkerLane> = options
        .iter()
        .filter(|option| option.harness.is_none())
        .map(lane)
        .collect();
    let harness_only = !omp.contains(current)
        && options
            .iter()
            .any(|option| option.harness.is_some() && lane(option) == *current);
    if harness_only {
        return None;
    }
    next_declared_lane(&omp, current)
}

/// Aggregates per-lane stall rates over delegation rows: each row counts
/// once as a worker on every lane it ran on, and each recorded stall counts
/// against the lane it happened on.
pub fn lane_stall_rates<'a>(
    links: impl IntoIterator<Item = &'a DelegationLink>,
) -> BTreeMap<String, LaneStallRate> {
    let mut rates: BTreeMap<String, LaneStallRate> = BTreeMap::new();
    for link in links {
        for lane in link.lanes() {
            let lane = lane.to_string();
            let stalls = link.stalls.iter().filter(|stall| **stall == lane).count();
            let rate = rates.entry(lane).or_default();
            rate.workers += 1;
            rate.stalls += u32::try_from(stalls).unwrap_or(u32::MAX);
            rate.stalled_workers += u32::from(stalls > 0);
        }
        let mut fell_back: BTreeSet<&str> = BTreeSet::new();
        for fallback in &link.gateway_fallbacks {
            let rate = rates.entry(fallback.lane.clone()).or_default();
            rate.fallback_requests = rate.fallback_requests.saturating_add(fallback.requests);
            if fell_back.insert(fallback.lane.as_str()) {
                rate.fallback_workers += 1;
            }
        }
    }
    rates
}

impl GovernedTaskOwner {
    /// Cancels and resumes stalled turns, switching lanes on a repeated stall.
    /// Failed sessions require Restart before SetModel or prompting.
    /// Re-read the durable phase between commands so a parent stop takes precedence.
    pub fn recover_stalled_children(&self, stall: Duration) -> Result<StallPass, String> {
        use odin_domain::huginn::{AbortScope, LiveCommandBody, LiveSessionState};
        let now = Self::clock_ms();
        let stall_ms = u64::try_from(stall.as_millis()).unwrap_or(u64::MAX);
        let mut pass = StallPass::default();
        for row in self.links.all_rows()? {
            let mut link = row.link;
            if link.phase != DelegationPhase::Running {
                continue;
            }
            let snapshot = match self.control.snapshot(link.child) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(
                        "odin-omp: delegated child stall check skipped child={} reason={error}",
                        link.child
                    );
                    continue;
                }
            };
            let quiet = snapshot.active
                && snapshot.state == Some(LiveSessionState::Running)
                && snapshot
                    .quiet_since_ms
                    .is_some_and(|since| now.saturating_sub(since) >= stall_ms);
            // Provider-failed turns rest rather than run quietly; handle each error once.
            let failed = snapshot.state == Some(LiveSessionState::Failed);
            let fault = snapshot.provider_fault.filter(|fault| {
                snapshot.active
                    && (snapshot.state == Some(LiveSessionState::Idle) || failed)
                    && link.handled_stall_event != Some(fault.event)
            });
            if let Some(fault) = fault.filter(|fault| fault.kind.refuses_lane()) {
                link.handled_stall_event = Some(fault.event);
                self.rotate_refused(&mut link, fault, failed, &mut pass)?;
                continue;
            }
            let provider_stall = fault.is_some();
            if !quiet && !provider_stall {
                continue;
            }
            if let Some(fault) = fault {
                link.handled_stall_event = Some(fault.event);
                tracing::warn!(
                    "odin-omp: delegated child stalled child={} lane={} cause={} event={}",
                    link.child,
                    link.current_lane(),
                    fault.kind.cause(),
                    fault.event
                );
            }
            let quiet_s = if quiet {
                snapshot
                    .quiet_since_ms
                    .map_or(0, |since| now.saturating_sub(since) / 1000)
            } else {
                stall_ms / 1000
            };
            let lane = link.current_lane();
            link.stalls.push(lane.to_string());
            let budget = MAX_STALL_RETRIES + u8::from(link.switched_to.is_some());
            if link.stall_retries >= budget {
                tracing::error!(
                    "odin-omp: delegated child stalled child={} lane={lane} quiet_s={quiet_s} \
                     action=end retries={}",
                    link.child,
                    link.stall_retries
                );
                if let Err(error) = self.control.stop_child(link.child) {
                    pass.failures.push(format!("{}: {error}", link.child));
                    continue;
                }
                self.write_link(&link.child, |fresh| {
                    fresh.phase = DelegationPhase::Ended;
                    fresh.stalls = link.stalls.clone();
                    fresh.handled_stall_event = link.handled_stall_event;
                    true
                })?;
                pass.ended.push(StalledOut {
                    child: link.child,
                    parent_seat: link.parent_seat.clone(),
                    stalls: link.stalls.clone(),
                });
                continue;
            }
            if quiet {
                // `command` returns once the actor applied the abort and
                // journaled its outcome: the resume below cannot race it.
                if let Err(error) = self.control.command(
                    link.child,
                    LiveCommandBody::Abort {
                        scope: AbortScope::CurrentTurn,
                    },
                ) {
                    pass.failures.push(format!(
                        "{}: the stalled turn was not cancelled: {error}",
                        link.child
                    ));
                    continue;
                }
            } else if failed {
                // The provider failed the turn and the session with it. The
                // error stays answered whatever the restart's verdict: a
                // refused restart is reported, never retried.
                match self.restart_failed_child(&link, link.switched_to.as_ref()) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        pass.failures.push(format!(
                            "{}: the failed turn was not restarted: {error}",
                            link.child
                        ));
                        self.write_link(&link.child, |fresh| {
                            if fresh.phase != DelegationPhase::Running {
                                return false;
                            }
                            fresh.handled_stall_event = link.handled_stall_event;
                            true
                        })?;
                        continue;
                    }
                }
            }
            // Cancellation and restart are synchronous, but an explicit
            // parent stop can land while they run. Never switch or resume
            // that ended task using this scan's earlier Running row.
            let Some(fresh) = self.links.load(&link.child)? else {
                continue;
            };
            if fresh.phase != DelegationPhase::Running {
                continue;
            }
            let repeated = link.stall_retries > 0;
            link.stall_retries += 1;
            if repeated && link.switched_to.is_none() {
                match self.switch_lane(&link, &lane) {
                    Ok(Some(next)) => {
                        tracing::warn!(
                            "odin-omp: delegated child stalled child={} quiet_s={quiet_s} \
                             action=switch from={lane} to={next}",
                            link.child
                        );
                        pass.switched.push(LaneSwitch {
                            child: link.child,
                            parent_seat: link.parent_seat.clone(),
                            from: lane.clone(),
                            to: next.clone(),
                            cause: ProviderFaultKind::Stall,
                        });
                        link.switched_to = Some(next);
                    }
                    Ok(None) => tracing::warn!(
                        "odin-omp: delegated child stalled child={} lane={lane} \
                         fallback=none (the seat declares no other launch option)",
                        link.child
                    ),
                    Err(error) => pass.failures.push(format!(
                        "{}: the lane fallback from {lane} failed: {error}",
                        link.child
                    )),
                }
            }
            self.write_link(&link.child, |fresh| {
                if fresh.phase != DelegationPhase::Running {
                    return false;
                }
                fresh.stalls = link.stalls.clone();
                fresh.stall_retries = link.stall_retries;
                fresh.switched_to = link.switched_to.clone();
                fresh.handled_stall_event = link.handled_stall_event;
                true
            })?;
            // SetModel can also cross a parent stop. The guarded write
            // above preserves its row and budget; this read suppresses
            // continuation. A stop after this read is still enforced by
            // the live actor's command admission, as for rollover.
            let Some(fresh) = self.links.load(&link.child)? else {
                continue;
            };
            if fresh.phase != DelegationPhase::Running {
                continue;
            }
            let message = format!(
                "[Odin] Your last step made no progress for {quiet_s} s (the model call \
                 stalled) and was cancelled. Continue the assigned unit from where you \
                 were; do not redo finished work."
            );
            match self.control.prompt(link.child, &message) {
                Ok(()) => {
                    tracing::warn!(
                        "odin-omp: delegated child stalled child={} lane={} quiet_s={quiet_s} \
                         action=resume retry={}/{}",
                        link.child,
                        link.current_lane(),
                        link.stall_retries,
                        MAX_STALL_RETRIES + u8::from(link.switched_to.is_some())
                    );
                    pass.resumed.push(link.child);
                }
                Err(error) => pass
                    .failures
                    .push(format!("{}: the resume was refused: {error}", link.child)),
            }
        }
        Ok(pass)
    }

    /// Moves provider-refused work to an untried declared lane, restarting failed
    /// sessions first. Authenticated context overflows roll over instead;
    /// other context refusals or exhausted lanes end the child.
    fn rotate_refused(
        &self,
        link: &mut DelegationLink,
        fault: ProviderTurnFault,
        failed: bool,
        pass: &mut StallPass,
    ) -> Result<(), String> {
        let lane = link.current_lane();
        let refused_on: BTreeSet<String> = link
            .refusals
            .iter()
            .map(|refusal| refusal.lane.clone())
            .chain(std::iter::once(lane.to_string()))
            .collect();
        // Only authenticated context overflow triggers rollover; provider overflow rotates lanes.
        let context_refusal = failed && fault.origin == ProviderFaultOrigin::ContextRefusal;
        if context_refusal && fault.kind == ProviderFaultKind::ContextOverflow {
            return self.rollover_refused_child(link, fault, &lane, pass);
        }
        let next = match self.control.next_launch_option(link.child, &lane) {
            Ok(_) if context_refusal => None,
            Ok(next) => next.filter(|next| !refused_on.contains(&next.to_string())),
            Err(error) => {
                pass.failures.push(format!(
                    "{}: the lane after the {} refusal on {lane} is unknown: {error}",
                    link.child,
                    fault.kind.cause()
                ));
                return self
                    .write_link(&link.child, |fresh| {
                        fresh.handled_stall_event = link.handled_stall_event;
                        true
                    })
                    .map(|_| ());
            }
        };
        if let Some(next) = &next {
            let switched = if failed {
                self.restart_failed_child(link, Some(next))
            } else {
                self.set_lane(link.child, next).map(|()| true)
            };
            match switched {
                Ok(true) => {}
                // A parent stop during restart takes precedence.
                Ok(false) => return Ok(()),
                Err(error) => {
                    pass.failures.push(format!(
                        "{}: the rotation from {lane} after a {} refusal failed: {error}",
                        link.child,
                        fault.kind.cause()
                    ));
                    return self
                        .write_link(&link.child, |fresh| {
                            fresh.handled_stall_event = link.handled_stall_event;
                            true
                        })
                        .map(|_| ());
                }
            }
        }
        link.refusals.push(LaneRefusal {
            lane: lane.to_string(),
            cause: fault.kind.cause().to_owned(),
            event: fault.event,
            next: next.as_ref().map(ToString::to_string),
        });
        let lineage = link
            .refusals
            .iter()
            .map(|refusal| format!("{}:{}", refusal.lane, refusal.cause))
            .collect::<Vec<_>>()
            .join(">");
        let Some(next) = next else {
            return self.end_refused_child(
                link,
                fault,
                lane.clone(),
                &lineage,
                pass,
                if context_refusal {
                    "its session failed on the refusal"
                } else {
                    "no declared lane left that has not refused"
                },
            );
        };
        link.switched_to = Some(next.clone());
        self.write_link(&link.child, |fresh| {
            fresh.switched_to = link.switched_to.clone();
            fresh.refusals = link.refusals.clone();
            fresh.handled_stall_event = link.handled_stall_event;
            true
        })?;
        tracing::warn!(
            "odin-omp: delegated child refused child={} cause={} event={} action=rotate \
             from={lane} to={next} lineage={lineage}",
            link.child,
            fault.kind.cause(),
            fault.event
        );
        pass.switched.push(LaneSwitch {
            child: link.child,
            parent_seat: link.parent_seat.clone(),
            from: lane,
            to: next.clone(),
            cause: fault.kind,
        });
        // SetModel can cross a parent stop: the stopped task is told
        // nothing more.
        if self
            .links
            .load(&link.child)?
            .is_none_or(|fresh| fresh.phase != DelegationPhase::Running)
        {
            return Ok(());
        }
        let message = format!(
            "[Odin] Your last model request was refused ({}), so you now run on {next}. \
             Continue the assigned unit from where you were; do not redo finished work.",
            fault.kind.plain()
        );
        if let Err(error) = self.control.prompt(link.child, &message) {
            pass.failures.push(format!(
                "{}: the resume on {next} was refused: {error}",
                link.child
            ));
        }
        Ok(())
    }

    /// Persists rollover admission before respawn; failed starts and exhausted
    /// budgets end the task. The bridge injects continuity; a concurrent parent stop wins.
    fn rollover_refused_child(
        &self,
        link: &mut DelegationLink,
        fault: ProviderTurnFault,
        lane: &WorkerLane,
        pass: &mut StallPass,
    ) -> Result<(), String> {
        if link.rollover_admissions >= MAX_ROLLOVER_ADMISSIONS {
            link.refusals.push(LaneRefusal {
                lane: lane.to_string(),
                cause: fault.kind.cause().to_owned(),
                event: fault.event,
                next: None,
            });
            let lineage = link
                .refusals
                .iter()
                .map(|refusal| format!("{}:{}", refusal.lane, refusal.cause))
                .collect::<Vec<_>>()
                .join(">");
            self.write_link(&link.child, |fresh| {
                fresh.refusals = link.refusals.clone();
                fresh.handled_stall_event = link.handled_stall_event;
                true
            })?;
            return self.end_refused_child(
                link,
                fault,
                lane.clone(),
                &lineage,
                pass,
                "its durable rollover budget is spent (two admissions); \
                 re-delegate the task",
            );
        }
        link.refusals.push(LaneRefusal {
            lane: lane.to_string(),
            cause: fault.kind.cause().to_owned(),
            event: fault.event,
            next: Some(lane.to_string()),
        });
        // The admission is counted when ATTEMPTED and is durable BEFORE
        // the respawn: a crash between the two never resets the budget.
        link.rollover_admissions = link.rollover_admissions.saturating_add(1);
        let lineage = link
            .refusals
            .iter()
            .map(|refusal| format!("{}:{}", refusal.lane, refusal.cause))
            .collect::<Vec<_>>()
            .join(">");
        self.write_link(&link.child, |fresh| {
            fresh.refusals = link.refusals.clone();
            fresh.rollover_admissions = link.rollover_admissions;
            fresh.handled_stall_event = link.handled_stall_event;
            true
        })?;
        match self.control.rollover(link.child, fault.event) {
            Ok(epoch_after) => {
                // The parent stop may have landed while the respawn ran:
                // only a still-Running link continues.
                let fresh = match self.links.load(&link.child) {
                    Ok(Some(fresh)) => fresh,
                    Ok(None) => {
                        pass.failures.push(format!(
                            "{}: the rollover lost its delegation row",
                            link.child
                        ));
                        return Ok(());
                    }
                    Err(error) => {
                        pass.failures.push(format!("{}: {error}", link.child));
                        return Ok(());
                    }
                };
                if fresh.phase != DelegationPhase::Running {
                    tracing::error!(
                        "odin-omp: delegated child refused child={} lane={lane} cause={} \
                         event={} action=superseded lineage={lineage} (the parent stop won \
                         the rollover race)",
                        link.child,
                        fault.kind.cause(),
                        fault.event
                    );
                    return Ok(());
                }
                tracing::warn!(
                    "odin-omp: delegated child refused child={} lane={lane} cause={} \
                     event={} action=rollover epoch={}..{epoch_after} \
                     admissions={}/{} lineage={lineage} (the fresh incarnation's one \
                     reinjection carries the durable brief and orders the work continued)",
                    link.child,
                    fault.kind.cause(),
                    fault.event,
                    epoch_after.saturating_sub(1),
                    link.rollover_admissions,
                    MAX_ROLLOVER_ADMISSIONS
                );
                Ok(())
            }
            Err(error) => {
                tracing::error!(
                    "odin-omp: delegated child refused child={} lane={lane} cause={} \
                     event={} action=rollover-failed lineage={lineage} (the child ends and \
                     its parent is told: {error})",
                    link.child,
                    fault.kind.cause(),
                    fault.event
                );
                self.end_refused_child(
                    link,
                    fault,
                    lane.clone(),
                    &lineage,
                    pass,
                    &format!("its fresh incarnation could not be started: {error}"),
                )
            }
        }
    }

    /// Stops the child before marking its row ended and reporting it to the parent.
    fn end_refused_child(
        &self,
        link: &mut DelegationLink,
        fault: ProviderTurnFault,
        lane: WorkerLane,
        lineage: &str,
        pass: &mut StallPass,
        reason: &str,
    ) -> Result<(), String> {
        tracing::error!(
            "odin-omp: delegated child refused child={} lane={lane} cause={} event={} \
             action=end lineage={lineage} ({reason})",
            link.child,
            fault.kind.cause(),
            fault.event
        );
        if let Err(error) = self.control.stop_child(link.child) {
            pass.failures.push(format!("{}: {error}", link.child));
            return self
                .write_link(&link.child, |fresh| {
                    fresh.refusals = link.refusals.clone();
                    fresh.handled_stall_event = link.handled_stall_event;
                    true
                })
                .map(|_| ());
        }
        self.write_link(&link.child, |fresh| {
            fresh.phase = DelegationPhase::Ended;
            fresh.refusals = link.refusals.clone();
            fresh.handled_stall_event = link.handled_stall_event;
            true
        })?;
        pass.refused.push(RefusedOut {
            child: link.child,
            parent_seat: link.parent_seat.clone(),
            lane,
            cause: fault.kind,
        });
        Ok(())
    }

    /// Moves one child to its seat's next declared lane through the live
    /// SetModel command; `Ok(None)` when the seat declares no other lane.
    fn switch_lane(
        &self,
        link: &DelegationLink,
        lane: &WorkerLane,
    ) -> Result<Option<WorkerLane>, String> {
        let Some(next) = self.control.next_launch_option(link.child, lane)? else {
            return Ok(None);
        };
        self.set_lane(link.child, &next)?;
        Ok(Some(next))
    }

    /// Puts one child on a declared lane through the live SetModel command.
    fn set_lane(&self, child: LiveSessionId, lane: &WorkerLane) -> Result<(), String> {
        use odin_domain::huginn::{LiveCommandBody, ModelName, ProviderName};
        let provider = ProviderName::new(lane.provider.clone())
            .map_err(|error| format!("declared provider {:?}: {error}", lane.provider))?;
        let model = ModelName::new(lane.model.clone())
            .map_err(|error| format!("declared model {:?}: {error}", lane.model))?;
        self.control
            .command(child, LiveCommandBody::SetModel { provider, model })
    }

    /// The actor-admitted way out of a turn the provider failed: a `Failed`
    /// session refuses SetModel and prompts and admits only the journaled
    /// `Restart`, which resumes the same transcript in a fresh incarnation
    /// running the launch pair. `lane`, when given, is set right after, so
    /// the child runs the lane its row records before it is told anything.
    /// `Ok(false)`: a parent stop landed during the restart and nothing
    /// more is sent.
    pub(crate) fn restart_failed_child(
        &self,
        link: &DelegationLink,
        lane: Option<&WorkerLane>,
    ) -> Result<bool, String> {
        self.control
            .command(link.child, odin_domain::huginn::LiveCommandBody::Restart)?;
        if self
            .links
            .load(&link.child)?
            .is_none_or(|fresh| fresh.phase != DelegationPhase::Running)
        {
            return Ok(false);
        }
        // A failure report without an epoch must not hide a new incarnation's failure.
        self.write_link(&link.child, |fresh| {
            if fresh.reported_answer.as_deref() == Some("failed-unproved") {
                fresh.reported_answer = None;
                true
            } else {
                false
            }
        })?;
        if let Some(lane) = lane {
            self.set_lane(link.child, lane)?;
        }
        Ok(true)
    }

    /// Records gateway fallbacks for running or recently created children.
    /// Merges into a fresh row to preserve concurrent changes; returns new or increased counts.
    pub fn observe_gateway_fallbacks(
        &self,
        served: &GatewayServedReader<'_>,
    ) -> Result<(Vec<FallbackSeen>, Vec<String>), String> {
        let now = Self::clock_ms();
        let (mut seen, mut failures) = (Vec::new(), Vec::new());
        for row in self.links.all_rows()? {
            let link = row.link;
            let recent = now.saturating_sub(link.created_at_ms) <= FALLBACK_OBSERVE_WINDOW_MS;
            if link.phase != DelegationPhase::Running && !recent {
                continue;
            }
            let counts = match served(&link.child, link.created_at_ms) {
                Ok(counts) => counts,
                Err(error) => {
                    failures.push(format!("child={} {error}", link.child));
                    continue;
                }
            };
            let Some(fresh) = self.links.load(&link.child)? else {
                continue;
            };
            let provider = self.declared_provider();
            let updated = gateway_fallbacks_seen(&fresh, &counts, provider);
            if updated == fresh.gateway_fallbacks {
                continue;
            }
            for fallback in &updated {
                let before = fresh
                    .gateway_fallbacks
                    .iter()
                    .find(|old| old.served == fallback.served);
                if before.map(|old| old.requests) != Some(fallback.requests) {
                    seen.push(FallbackSeen {
                        child: fresh.child,
                        parent_seat: fresh.parent_seat.clone(),
                        fallback: fallback.clone(),
                        first: before.is_none(),
                    });
                }
            }
            self.write_link(&link.child, |current| {
                let provider = self.declared_provider();
                let merged = gateway_fallbacks_seen(current, &counts, provider);
                if current.gateway_fallbacks == merged {
                    return false;
                }
                current.gateway_fallbacks = merged;
                true
            })?;
        }
        Ok((seen, failures))
    }

    pub fn lane_stall_rates(&self) -> Result<BTreeMap<String, LaneStallRate>, String> {
        Ok(lane_stall_rates(
            self.links.all_rows()?.iter().map(|row| &row.link),
        ))
    }

    /// Retires children past the hard or idle timeout unless they await live work.
    /// Stop failures retain their phase for the next pass.
    pub fn retire_timed_out_children(
        &self,
        timeout: Duration,
        idle: Option<Duration>,
    ) -> Result<(Vec<LiveSessionId>, Vec<String>), String> {
        let now = Self::clock_ms();
        let as_ms = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let timeout_ms = as_ms(timeout);
        let (mut retired, mut failures) = (Vec::new(), Vec::new());
        for row in self.links.all_rows()? {
            let mut link = row.link;
            if !matches!(
                link.phase,
                DelegationPhase::Provisioning | DelegationPhase::Running
            ) {
                continue;
            }
            let snapshot = match self.control.snapshot(link.child) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    failures.push(format!(
                        "{}: snapshot unreadable, skipped this round: {error}",
                        link.child
                    ));
                    continue;
                }
            };
            let active = snapshot.active;
            let idled_out = match (idle, snapshot.settled_since_ms) {
                (Some(idle), Some(since)) => now.saturating_sub(since) >= as_ms(idle),
                _ => false,
            };
            if now.saturating_sub(link.created_at_ms) < timeout_ms && !idled_out {
                continue;
            }
            match self.waiting_on_live_work(&link) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    failures.push(format!(
                        "{}: could not tell if it still holds work, skipped this round: {error}",
                        link.child
                    ));
                    continue;
                }
            }
            if active {
                if let Err(error) = self.control.stop_child(link.child) {
                    failures.push(format!("{}: {error}", link.child));
                    continue;
                }
            }
            self.write_link(&link.child, |fresh| {
                fresh.phase = DelegationPhase::Ended;
                true
            })?;
            link.phase = DelegationPhase::Ended;
            self.run_completion_capture(&mut link);
            retired.push(link.child);
        }
        Ok((retired, failures))
    }

    /// Marks running rows ended when the supervisor no longer has an active child.
    pub(super) fn reconcile(
        &self,
        link: &mut DelegationLink,
    ) -> Result<ChildLifecycleSnapshot, TaskToolFailure> {
        let snapshot = self
            .control
            .snapshot(link.child)
            .map_err(|error| TaskToolFailure::new("lifecycle_unavailable", error))?;
        if !snapshot.active && link.phase == DelegationPhase::Running {
            self.write_link(&link.child, |fresh| {
                fresh.phase = DelegationPhase::Ended;
                true
            })
            .map_err(|error| TaskToolFailure::new("link_persistence_failed", error))?;
            link.phase = DelegationPhase::Ended;
        }
        Ok(snapshot)
    }

    /// Stops a child after setup failure before persisting a terminal phase.
    /// A failed stop leaves the row running so later parent cleanup still finds it.
    pub(super) fn fail_open_child(
        &self,
        link: &mut DelegationLink,
        mut failure: TaskToolFailure,
    ) -> TaskToolFailure {
        failure.effect_may_have_started = true;
        match self.control.stop_child(link.child) {
            Ok(_) => link.phase = DelegationPhase::Failed,
            Err(error) => {
                failure.detail.push_str(&format!(
                    "; the opened child {} was not verifiably stopped ({error}); \
                     the row stays counted live for the parent-stop barrier",
                    link.child
                ));
                link.phase = DelegationPhase::Running;
            }
        }
        if let Err(error) = self.write_link(&link.child, |fresh| {
            fresh.phase = link.phase;
            true
        }) {
            failure.detail.push_str(&format!(
                "; failed to persist the failed delegation row: {error}"
            ));
        }
        tracing::error!(
            "odin-omp: delegation failed after open child={} parent_seat={:?} kind={} phase={:?} \
             detail={}",
            link.child,
            link.parent_seat,
            failure.kind,
            link.phase,
            failure.detail
        );
        failure
    }
}

impl ChildStopCoordinator for GovernedTaskOwner {
    fn await_children_on_stop(
        &self,
        parent: LiveSessionId,
        budget: Duration,
    ) -> Result<Vec<ChildStopRecord>, String> {
        // Defer reviews until stop calls finish; unwinding leaves them pending.
        let scope = self.open_stop(parent);
        let mut review = BTreeSet::new();
        let stopped = self.stop_children(parent, budget, &mut review);
        review.extend(scope.close());
        // Reviews have their own timeout and must not consume a stop deadline.
        // An ancestor still stopping receives these reviews instead.
        for child in review {
            match self.links.load(&child) {
                Ok(Some(mut row)) => self.run_completion_capture(&mut row),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    "odin-omp: delegation capture deferred child={child} reason=row unreadable \
                     after the stop of {parent}: {error}"
                ),
            }
        }
        stopped
    }
}

impl GovernedTaskOwner {
    /// Stops children before retiring the parent's capsule, collecting ended rows for later review.
    fn stop_children(
        &self,
        parent: LiveSessionId,
        budget: Duration,
        ended: &mut BTreeSet<LiveSessionId>,
    ) -> Result<Vec<ChildStopRecord>, String> {
        let deadline = std::time::Instant::now() + budget;
        let parent_session = SessionId::new(parent.to_string())
            .map_err(|error| format!("parent session {parent} is invalid: {error}"))?;
        if let Some(successor) = self.links.armed_successor(&parent_session)? {
            return self.handoff_children(parent, &parent_session, &successor, deadline);
        }
        let mut records = Vec::new();
        // Stop-barrier companion: a row an in-flight task_create still lands
        // must not race past the descendant enumeration, so keep re-reading
        // the durable ledger until a pass finds nothing live that has not
        // already been attempted.
        let mut attempted: BTreeSet<LiveSessionId> = BTreeSet::new();
        loop {
            let mut processed = false;
            for mut row in self.links.children_of(&parent_session)? {
                if !matches!(
                    row.phase,
                    DelegationPhase::Provisioning | DelegationPhase::Running
                ) {
                    continue;
                }
                if !attempted.insert(row.child) {
                    continue;
                }
                processed = true;
                let snapshot = self.control.snapshot(row.child)?;
                if !snapshot.active {
                    self.write_link(&row.child, |fresh| {
                        fresh.phase = DelegationPhase::Ended;
                        true
                    })?;
                    row.phase = DelegationPhase::Ended;
                    records.push(ChildStopRecord {
                        child: row.child,
                        stopped: true,
                        handed_off: false,
                        detail: Some("already inactive when the parent stopped".to_owned()),
                    });
                    ended.insert(row.child);
                    continue;
                }
                // Successful teardown includes nested children and capsule retirement; no poll is needed.
                match self.control.stop_child(row.child) {
                    Ok(_) => {
                        self.write_link(&row.child, |fresh| {
                            fresh.phase = DelegationPhase::Ended;
                            true
                        })?;
                        row.phase = DelegationPhase::Ended;
                        records.push(ChildStopRecord {
                            child: row.child,
                            stopped: true,
                            handed_off: false,
                            detail: None,
                        });
                        ended.insert(row.child);
                    }
                    Err(error) => {
                        // On stop failure, wait for observed termination within the remaining budget.
                        match self.control.await_stop(row.child, deadline.saturating_duration_since(std::time::Instant::now())) {
                            Ok(true) => {
                                self.write_link(&row.child, |fresh| {
                                    fresh.phase = DelegationPhase::Ended;
                                    true
                                })?;
                                row.phase = DelegationPhase::Ended;
                                records.push(ChildStopRecord {
                                    child: row.child,
                                    stopped: true,
                                    handed_off: false,
                                    detail: Some(format!(
                                        "stop request failed ({error}), but the child was observed stopped"
                                    )),
                                });
                                ended.insert(row.child);
                            }
                            Ok(false) => records.push(ChildStopRecord {
                                child: row.child,
                                stopped: false,
                                handed_off: false,
                                detail: Some(format!(
                                    "stop request failed ({error}) and the child did not stop within the bounded budget"
                                )),
                            }),
                            Err(await_error) => records.push(ChildStopRecord {
                                child: row.child,
                                stopped: false,
                                handed_off: false,
                                detail: Some(format!(
                                    "stop request failed ({error}); bounded await failed: {await_error}"
                                )),
                            }),
                        }
                    }
                }
            }
            if !processed {
                break;
            }
        }
        let unresolved: Vec<String> = records
            .iter()
            .filter(|record| !record.stopped)
            .map(|record| {
                format!(
                    "child {}: {}",
                    record.child,
                    record
                        .detail
                        .clone()
                        .unwrap_or_else(|| "no stop evidence".to_owned())
                )
            })
            .collect();
        // Root and child share this closure: the stopping session retires its
        // own capsule only after every delegated child is verified stopped,
        // so no private sidecar backend outlives a successful stop. A failure
        // above keeps the session fail-closed with its capsule intact.
        if !unresolved.is_empty() {
            return Err(unresolved.join("; "));
        }
        self.control.retire_capsule_on_stop(parent, deadline)?;
        Ok(records)
    }

    /// Re-points live children to the successor; a write failure stops nothing.
    fn handoff_children(
        &self,
        parent: LiveSessionId,
        parent_session: &SessionId,
        successor: &SessionId,
        deadline: std::time::Instant,
    ) -> Result<Vec<ChildStopRecord>, String> {
        let mut records = Vec::new();
        let mut attempted = BTreeSet::new();
        loop {
            let mut processed = false;
            for row in self.links.children_of(parent_session)? {
                if !matches!(
                    row.phase,
                    DelegationPhase::Provisioning | DelegationPhase::Running
                ) {
                    continue;
                }
                if !attempted.insert(row.child) {
                    continue;
                }
                processed = true;
                self.write_link(&row.child, |fresh| {
                    if fresh.parent == *successor {
                        return false;
                    }
                    fresh.parent = successor.clone();
                    true
                })?;
                let child = row.child;
                tracing::info!(
                    "odin-omp: delegated child handed to successor child={child} from={parent} to={successor}"
                );
                records.push(ChildStopRecord {
                    child: row.child,
                    stopped: false,
                    handed_off: true,
                    detail: Some(format!("handed to successor {successor}; still running")),
                });
            }
            if !processed {
                break;
            }
        }
        self.links.clear_successor(parent_session)?;
        self.control.retire_capsule_on_stop(parent, deadline)?;
        Ok(records)
    }

    /// True while a grandchild still runs or an escalation is still unanswered.
    fn waiting_on_live_work(&self, link: &DelegationLink) -> Result<bool, String> {
        if link.escalation_open {
            return Ok(true);
        }
        let child_session = SessionId::new(link.child.to_string())
            .map_err(|error| format!("child session {} is invalid: {error}", link.child))?;
        Ok(self
            .links
            .children_of(&child_session)?
            .into_iter()
            .any(|row| {
                matches!(
                    row.phase,
                    DelegationPhase::Provisioning | DelegationPhase::Running
                )
            }))
    }
}
