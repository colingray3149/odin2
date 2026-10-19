//! Rebuilds intent queues from durable rows and reconciles them through the configured routes.

use std::future::Future;
use std::sync::Arc;

use super::{now_utc, ApprovedIntentExecution, HermesRuntime, HermesRuntimeError, IntentFailure};
use crate::ingress::{DiscordIngress, PendingApproval};
use odin_domain::{ApprovalStatus, CommandId};
use serde_json::{json, Value};

/// Runs the future in a separate runtime to avoid nested-runtime panics;
/// joining the scoped thread preserves serial reconciliation.
pub(super) fn bridge_route<T>(
    future: impl Future<Output = T> + Send,
) -> Result<T, HermesRuntimeError>
where
    T: Send,
{
    std::thread::scope(|scope| {
        let joined = scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        HermesRuntimeError::Composition(format!(
                            "intent route bridge runtime unavailable: {error}"
                        ))
                    })?;
                Ok(runtime.block_on(future))
            })
            .join();
        joined.map_err(|_| {
            HermesRuntimeError::Composition("the intent route bridge thread panicked".to_owned())
        })?
    })
}

fn approved_intent(
    receipt: &crate::ingress::TaskReceipt,
    accepted: &odin_ledger::command::AcceptedCommand,
) -> ApprovedIntentExecution {
    ApprovedIntentExecution {
        command_id: receipt.command_id.to_string(),
        idempotency_key: receipt.idempotency_key.clone(),
        content: accepted
            .command()
            .arguments
            .get("request")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        unprompted: false,
    }
}

/// Runs one batch through the route on the bridge thread: one outcome per
/// intent, in order.
fn run_batch(
    route: &Arc<dyn super::ApprovedIntentRoute>,
    intents: Vec<ApprovedIntentExecution>,
) -> Vec<Result<Value, IntentFailure>> {
    let count = intents.len();
    match bridge_route(route.execute_batch(intents)) {
        Ok(outcomes) => outcomes,
        Err(error) => vec![Err(IntentFailure::Other(error.to_string())); count],
    }
}

impl HermesRuntime {
    /// Settles terminal approvals without effects and dispatches approved intents.
    /// Missing routes leave intents queued for a later reconciliation pass.
    pub fn reconcile_gated_tasks(&self) -> Result<usize, HermesRuntimeError> {
        let ingress = match &self.ingress {
            Some(ingress) => ingress,
            None => return Ok(0),
        };
        // Release the stash lock before waiting for answers so new DMs can be admitted.
        let mut pending = {
            let mut stash = self
                .gated
                .lock()
                .map_err(|_| HermesRuntimeError::Composition("gated stash poisoned".to_owned()))?;
            std::mem::take(&mut *stash)
        };
        let route = self
            .approved_route
            .lock()
            .ok()
            .and_then(|cell| cell.clone());
        let mut settled = 0;
        let mut kept = Vec::new();
        let mut batch = Vec::new();
        for (receipt, pending) in pending.drain(..) {
            let approval = match self.store.approval(&pending.approval_id) {
                Ok(Some(approval)) => approval,
                Ok(None) => continue,
                Err(error) => {
                    tracing::error!(error = %error, "odin-hermes could not read a gated intent's approval: {error}");
                    kept.push((receipt, pending));
                    continue;
                }
            };
            let terminal = matches!(
                approval.status,
                ApprovalStatus::Denied | ApprovalStatus::Expired | ApprovalStatus::Cancelled
            );
            // Consumed approvals remain eligible after a crash; `gate_effect` resumes them idempotently.
            let approved = matches!(
                approval.status,
                ApprovalStatus::Approved | ApprovalStatus::Consumed
            );
            if !terminal && !approved {
                kept.push((receipt, pending));
                continue;
            }
            let gate = match ingress.gate_effect(
                &receipt,
                &pending.approval_id,
                approval.revision,
                now_utc(),
            ) {
                Ok(gate) => gate,
                Err(error) => {
                    tracing::error!(error = %error, "odin-hermes could not gate an intent: {error}");
                    kept.push((receipt, pending));
                    continue;
                }
            };
            if let crate::ingress::EffectGate::Approved { accepted } = gate {
                // Keep the intent queued until its route is installed; gate consumption is idempotent.
                if route.is_none() {
                    kept.push((receipt, pending));
                    continue;
                }
                let intent = approved_intent(&receipt, &accepted);
                batch.push((accepted, intent));
            }
            settled += 1;
        }
        // A crash before settlement replays each command's idempotency key;
        // batching lets the route answer waiting messages in one turn.
        if let (Some(route), false) = (route, batch.is_empty()) {
            let (accepted, intents): (Vec<_>, Vec<_>) = batch.into_iter().unzip();
            let outcomes = run_batch(&route, intents);
            let mut failure_told = false;
            for (accepted, outcome) in accepted.iter().zip(outcomes) {
                match outcome {
                    Ok(projection) => {
                        let result = json!({ "status": "executed", "outcome": projection });
                        if let Err(error) = ingress.settle_effect(accepted, result, now_utc()) {
                            tracing::error!(error = %error, "odin-hermes could not settle an approved intent: {error}");
                        }
                    }
                    Err(reason) => {
                        // Honest terminal + one plain-language notice: the
                        // owner's DM never goes silent on a failed answer,
                        // and the typed detail stays out of it.
                        if let Err(error) =
                            ingress.settle_effect_failure(accepted, reason.to_string(), now_utc())
                        {
                            tracing::error!(
                                error = %error,
                                "odin-hermes could not settle a failed approved intent: {error}"
                            );
                        }
                        if !failure_told {
                            self.notify_intent_failure(
                                "intent-result",
                                accepted.command().id.as_str(),
                                &reason,
                            );
                            failure_told = true;
                        }
                    }
                }
            }
        }
        if !kept.is_empty() {
            if let Ok(mut stash) = self.gated.lock() {
                stash.splice(0..0, kept);
            }
        }
        Ok(settled)
    }

    /// Drives the admitted (non-gated) intent queue once. Every queued
    /// admitted intent is presented at the executable boundary exactly
    /// like the gated leg — governance re-proved from the durable row,
    /// acceptance made durable — and then follows the SAME daemon-bound
    /// conversation route:
    ///
    /// - the route's settled human-readable answer is what the task
    ///   settles with (`completed`, projection recorded);
    /// - a typed route refusal settles the task durably `failed` AND
    ///   tells the owner's paired DM channel in plain language — never
    ///   silence;
    /// - an unbound route holds the queue fail-closed: intents stay
    ///   queued, never settled as failed for a missing deployment;
    /// - a settle failure keeps the intent and STOPS the drain: the next
    ///   tick replays it through the route's idempotency key before any
    ///   later intent executes, so one owner never receives a duplicated
    ///   answer.
    pub fn reconcile_admitted_intents(&self) -> Result<usize, HermesRuntimeError> {
        let ingress = match &self.ingress {
            Some(ingress) => ingress,
            None => return Ok(0),
        };
        // Rebuild the in-memory queue from durable rows after rechecking governance.
        self.recover_intent_rows(ingress)?;
        // Drained under the lock, executed WITHOUT it: the route's answer
        // bound is minutes, and a paired DM arriving meanwhile must admit
        // immediately on the gateway thread — never queue behind an
        // answer wait. Held-back entries are prepended when the drain
        // finishes, preserving execution order.
        let mut pending = {
            let mut queue = self.admitted.lock().map_err(|_| {
                HermesRuntimeError::Composition("admitted queue poisoned".to_owned())
            })?;
            std::mem::take(&mut *queue)
        };
        let route = self
            .approved_route
            .lock()
            .ok()
            .and_then(|cell| cell.clone());
        let Some(route) = route else {
            if !pending.is_empty() {
                tracing::warn!(
                    "odin-hermes: the conversation route is unbound; {} admitted intent(s) \
                     are held fail-closed",
                    pending.len()
                );
            }
            if let Ok(mut queue) = self.admitted.lock() {
                queue.splice(0..0, pending);
            }
            return Ok(0);
        };
        let mut settled = 0;
        let mut kept = Vec::new();
        let mut batch = Vec::new();
        for receipt in pending.drain(..) {
            match ingress.accept_admitted(&receipt, now_utc()) {
                Ok(crate::ingress::AdmittedAccept::Accepted(accepted)) => {
                    let intent = approved_intent(&receipt, &accepted);
                    batch.push((receipt, accepted, intent));
                }
                Ok(crate::ingress::AdmittedAccept::Rejected { reason }) => {
                    // Governance refused at the executable boundary; the
                    // row is terminally rejected and leaves the queue.
                    tracing::error!(
                        reason = %reason,
                        "odin-hermes: governance refused an admitted intent at execution: \
                         {reason}"
                    );
                    settled += 1;
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "odin-hermes could not present an admitted intent for execution: \
                         {error}"
                    );
                    kept.push(receipt);
                }
            }
        }
        // Dropped from the queue before execution: a crash between the
        // execute and the durable settle replays through the route's
        // idempotency key, exactly once. Messages that waited together run
        // as one batch, so the route can answer them in one turn.
        let intents: Vec<_> = batch.iter().map(|(_, _, intent)| intent.clone()).collect();
        let outcomes = if intents.is_empty() {
            Vec::new()
        } else {
            run_batch(&route, intents)
        };
        let mut failure_told = false;
        let mut entries = batch.into_iter().zip(outcomes);
        for ((receipt, accepted, _), outcome) in entries.by_ref() {
            settled += 1;
            let keep = match outcome {
                Ok(projection) => {
                    // Delivery belongs to the route's durable state machine.
                    // A failed acknowledgement may still mean the send landed.
                    let result = json!({ "status": "executed", "outcome": projection });
                    match ingress.settle_effect(&accepted, result, now_utc()) {
                        Ok(()) => false,
                        Err(error) => {
                            tracing::error!(error = %error, "odin-hermes could not settle an admitted intent: {error}");
                            true
                        }
                    }
                }
                Err(reason) => {
                    match ingress.settle_effect_failure(&accepted, reason.to_string(), now_utc()) {
                        Ok(()) => {
                            if !failure_told {
                                self.notify_intent_failure(
                                    "intent-result",
                                    receipt.command_id.as_str(),
                                    &reason,
                                );
                                failure_told = true;
                            }
                            false
                        }
                        Err(error) => {
                            tracing::error!(
                                error = %error,
                                "odin-hermes could not settle a failed admitted intent: {error}"
                            );
                            true
                        }
                    }
                }
            };
            if keep {
                // Settle this replay before newer intents replace its cached result and duplicate its answer.
                kept.push(receipt);
                kept.extend(entries.map(|((receipt, _, _), _)| receipt));
                break;
            }
        }
        if !kept.is_empty() {
            if let Ok(mut queue) = self.admitted.lock() {
                queue.splice(0..0, kept);
            }
        }
        Ok(settled)
    }

    /// Rebuilds the reconcile queues from the durable rows: the intent row
    /// is the enqueue, so entries lost with the in-memory stashes are
    /// re-derived here, deduped against whatever is still queued.
    fn recover_intent_rows(&self, ingress: &Arc<DiscordIngress>) -> Result<(), HermesRuntimeError> {
        let rows = self.store.tasks().map_err(HermesRuntimeError::from)?;
        let queued = |id: &str| -> bool {
            self.admitted
                .lock()
                .map(|queue| {
                    queue
                        .iter()
                        .any(|receipt| receipt.command_id.as_str() == id)
                })
                .unwrap_or(false)
                || self
                    .gated
                    .lock()
                    .map(|stash| {
                        stash
                            .iter()
                            .any(|(receipt, _)| receipt.command_id.as_str() == id)
                    })
                    .unwrap_or(false)
        };
        for row in rows {
            if !row
                .id
                .as_str()
                .starts_with(crate::ingress::INTENT_COMMAND_PREFIX)
            {
                continue;
            }
            if queued(row.id.as_str()) {
                continue;
            }
            match ingress.recover_intent(&row, now_utc()) {
                Ok(Some(crate::ingress::RecoveredIntent::Admitted(receipt))) => {
                    self.stash_admitted(receipt);
                }
                Ok(Some(crate::ingress::RecoveredIntent::Expired {
                    command_id,
                    content,
                })) => {
                    // Tell the owner an unsettled message expired instead of dropping it silently.
                    tracing::warn!(
                        command = %command_id,
                        "odin-hermes: intent {command_id} expired unsettled; asking the \
                         owner to resend"
                    );
                    let notice = crate::conversation::prompt::unknown_fate_notice(&content);
                    if let Err(error) =
                        self.notify_reply("intent-result", command_id.as_str(), &notice)
                    {
                        tracing::error!(error = %error, "odin-hermes could not deliver the expiry notice: {error}");
                    }
                }
                Ok(Some(crate::ingress::RecoveredIntent::Gated(receipt, pending))) => {
                    // The pairing decision the crashed process recorded at
                    // admit is replayed for a still-pending approval: the
                    // paired owner's own message is the operator approval
                    // record, exactly as at admit.
                    self.replay_pairing_approval(ingress, &pending, &receipt.command_id);
                    self.stash_gated(receipt, pending);
                }
                Ok(None) => {}
                Err(error) => {
                    // Typed per-row failure (e.g. governance unavailable):
                    // the row stays durable and the next tick retries.
                    tracing::error!(intent = %row.id, error = %error, "odin-hermes could not recover intent {}: {error}", row.id);
                }
            }
        }
        Ok(())
    }

    /// Records the pairing approval for one recovered gated intent whose
    /// approval is still pending: the same decision admit would have made.
    fn replay_pairing_approval(
        &self,
        ingress: &Arc<DiscordIngress>,
        pending: &PendingApproval,
        command_id: &CommandId,
    ) {
        let approval = match self.store.approval(&pending.approval_id) {
            Ok(Some(approval)) => approval,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    approval = %pending.approval_id,
                    error = %error,
                    "odin-hermes: pairing approval replay skipped approval={} reason={error}",
                    pending.approval_id
                );
                return;
            }
        };
        if approval.status != ApprovalStatus::Requested {
            return;
        }
        let author = self
            .store
            .task(command_id)
            .ok()
            .flatten()
            .and_then(|row| {
                row.arguments
                    .get("author_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let decided_by = format!("discord-owner:{author}");
        if let Err(error) = ingress.decide_effect_approval(
            pending,
            odin_ledger::approval::ApprovalDecision::Approve { evidence_ref: None },
            &decided_by,
            now_utc(),
        ) {
            tracing::error!(command = %command_id, error = %error, "odin-hermes could not replay the owner approval for {command_id}: {error}");
        }
    }

    /// One plain-language failure notice to the owner's paired DM channel:
    /// a route failure is never silent. The typed variant renders exactly
    /// one natural sentence (no ids, no typed detail); the full reason goes
    /// to the daemon log and the durable settlement, never to Discord.
    pub(super) fn notify_intent_failure(&self, kind: &str, key: &str, failure: &IntentFailure) {
        tracing::error!(failure = %failure, "odin-hermes intent failure: {failure}");
        let notice = crate::natural::natural_intent_failure(failure);
        if let Err(error) = self.notify_reply(kind, key, &notice) {
            tracing::error!(error = %error, "odin-hermes could not deliver an intent failure notice: {error}");
        }
    }
}
