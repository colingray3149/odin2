//! Terminal result capture deferred until dependent stops finish.

use std::collections::BTreeMap;

use odin_domain::huginn::LiveSessionId;

use super::{GovernedTaskOwner, OpenStop, TaskCompletionFacts};
use crate::host_tools::delegation::contracts::live_session_id;
use crate::host_tools::delegation::links::{DelegationLink, DelegationPhase};
use crate::host_tools::delegation::vocabulary::TaskResultReport;

impl GovernedTaskOwner {
    /// Reviews the latest durable result of a terminal row. All capture
    /// callers share the capture gate and reload after acquiring it; only
    /// fresh-row mutations hold the separate observer gate.
    pub(in crate::host_tools::delegation) fn run_completion_capture(
        &self,
        link: &mut DelegationLink,
    ) {
        // Checked before the capture gate, which a running review holds, so
        // a stop closure handing its ended children up never waits on one.
        if self.held_for_open_stop(link) {
            return;
        }
        let _capturing = self.capturing.lock();
        let Ok(Some(current)) = self.links.load(&link.child) else {
            return;
        };
        *link = current;
        // Again for a row that ended while this caller waited at the gate.
        if self.held_for_open_stop(link) {
            return;
        }
        self.capture_terminal_result(link);
    }

    /// Defers review to an ancestor's last stop call, updating the observed result
    /// marker first. Unknown lineage leaves capture pending while any stop is open.
    fn held_for_open_stop(&self, link: &mut DelegationLink) -> bool {
        if self.learning.is_none() || self.stopping.lock().is_empty() {
            return false;
        }
        let current = match self.links.load(&link.child) {
            Ok(Some(current)) => current,
            Ok(None) => return false,
            Err(error) => {
                tracing::warn!(
                    "odin-omp: delegation capture deferred child={} reason=row unreadable while a \
                     stop is open: {error}",
                    link.child
                );
                return true;
            }
        };
        *link = current;
        if link.phase != DelegationPhase::Ended {
            return false;
        }
        let lineage = match self.stop_lineage(link) {
            Ok(lineage) => lineage,
            Err(error) => {
                tracing::warn!(
                    "odin-omp: delegation capture deferred child={} reason=lineage unproved while a \
                     stop is open: {error}",
                    link.child
                );
                return true;
            }
        };
        let open = |stopping: &BTreeMap<LiveSessionId, OpenStop>| {
            lineage
                .into_iter()
                .flatten()
                .find(|session| stopping.contains_key(session))
        };
        if open(&self.stopping.lock()).is_none() {
            return false;
        }
        let _ = self.observe_latest_result(link);
        let mut stopping = self.stopping.lock();
        let Some(session) = open(&stopping) else {
            // The scope closed meanwhile: nothing waits on this child now.
            return false;
        };
        if let Some(scope) = stopping.get_mut(&session) {
            scope.deferred.insert(link.child);
        }
        true
    }

    /// Parent and, at depth two, grandparent, nearest first; other shapes are errors.
    fn stop_lineage(&self, link: &DelegationLink) -> Result<[Option<LiveSessionId>; 2], String> {
        let parent = live_session_id(&link.parent)?;
        match link.depth {
            1 => Ok([Some(parent), None]),
            2 => {
                let row = self
                    .links
                    .load(&parent)?
                    .ok_or_else(|| format!("its parent {parent} has no delegation row"))?;
                let grandparent = live_session_id(&row.parent)?;
                if row.depth != 1 || grandparent == link.child || grandparent == parent {
                    return Err(format!(
                        "its parent {parent} records depth {} under {grandparent}",
                        row.depth
                    ));
                }
                Ok([Some(parent), Some(grandparent)])
            }
            depth => Err(format!("it records unsupported delegation depth {depth}")),
        }
    }

    /// Reads the child's latest durable result and raises the row's
    /// monotonic result marker to it; the capture marker is untouched.
    /// `None` when the history is unreadable (reported, still pending), holds
    /// no result yet, or the row could not be written.
    fn observe_latest_result(&self, link: &mut DelegationLink) -> Option<TaskResultReport> {
        let result = match self.control.last_result(link.child) {
            // A read failure leaves capture pending.
            Err(error) => {
                tracing::error!(
                    "odin-omp: delegation capture deferred child={} reason=result read failed: {error}",
                    link.child
                );
                return None;
            }
            // A late result remains capturable; absence is not finality.
            Ok(result) => result?,
        };
        let child = link.child;
        self.write_link(&child, |fresh| {
            let raised = fresh.phase == DelegationPhase::Ended
                && fresh
                    .learning_result_sequence
                    .is_none_or(|sequence| sequence < result.event_sequence);
            if raised {
                fresh.learning_result_sequence = Some(result.event_sequence);
            }
            link.phase = fresh.phase;
            link.learning_result_sequence = fresh.learning_result_sequence;
            link.learning_capture_sequence = fresh.learning_capture_sequence;
            raised
        })
        .ok()?;
        Some(result)
    }

    fn capture_terminal_result(&self, link: &mut DelegationLink) {
        if link.phase != DelegationPhase::Ended {
            return;
        }
        let Some(capture) = self.learning.as_ref() else {
            return;
        };
        let Some(result) = self.observe_latest_result(link) else {
            return;
        };
        if link.phase != DelegationPhase::Ended
            || link
                .learning_result_sequence
                .is_some_and(|sequence| sequence > result.event_sequence)
        {
            // History has not caught up with the durable observer receipt.
            return;
        }
        if link
            .learning_capture_sequence
            .is_some_and(|sequence| sequence >= result.event_sequence)
        {
            return;
        }
        let Some(parent_seat) = link.parent_seat.clone() else {
            // Missing parent attribution must not be guessed.
            return;
        };
        let previous_capture = link.learning_capture_sequence;
        let sequence = result.event_sequence;
        match capture.capture_task_completion(&TaskCompletionFacts {
            parent_seat,
            parent_session: link.parent.clone(),
            child: link.child,
            result,
        }) {
            Ok(()) => {
                // Persist only this exact result's marker on the fresh row:
                // result receipts and report intents written during review
                // survive. A later result remains eligible for its own review.
                match self.write_link(&link.child, |fresh| {
                    if fresh
                        .learning_capture_sequence
                        .is_some_and(|captured| captured >= sequence)
                    {
                        return false;
                    }
                    fresh.learning_capture_sequence = Some(sequence);
                    true
                }) {
                    Ok(Some(())) | Ok(None) => {
                        link.learning_capture_sequence = Some(sequence);
                    }
                    Err(error) => {
                        link.learning_capture_sequence = previous_capture;
                        tracing::warn!(
                            "odin-omp: delegation capture deferred child={} reason={error}",
                            link.child
                        );
                    }
                }
            }
            // Failure leaves the exact result pending and retryable.
            Err(error) => {
                tracing::warn!(
                    "odin-omp: delegation capture deferred child={} reason={error}",
                    link.child
                );
            }
        }
    }
}
