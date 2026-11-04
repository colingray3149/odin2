use super::*;
use crate::live::ledger::REPLAY_PAGE_EVENTS;

pub(super) fn remove_capture_once(
    terminal: &ZellijLiveAdapter,
    teardown: &mut Teardown,
    session: &impl std::fmt::Display,
) {
    if teardown.capture_removed {
        return;
    }
    teardown.capture_removed = true;
    if let Err(error) = terminal.remove_capture() {
        tracing::error!("odind: terminal-capture remove-failed session={session} reason={error}");
    }
}

pub(super) async fn admit_fresh_command(
    command: LiveCommand,
    handoff: Vec<u8>,
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>,
) -> Result<CommandReceipt, LiveError> {
    if let Some(existing) = ledger.command(&command).await.map_err(live_error)? {
        if ledger
            .fresh_handoff(&command)
            .await
            .map_err(live_error)?
            .is_none()
        {
            return Err(LiveError::Conflict {
                code: "fresh_command_conflict".to_owned(),
                message: "the command was already admitted for ordinary dispatch".to_owned(),
            });
        }
        return Ok(existing.receipt);
    }
    let snapshot = summary.read().map_err(unavailable)?.clone();
    let target = LiveCommandTarget {
        session_id: snapshot.session_id,
        epoch: snapshot.epoch,
        event_head: snapshot.event_head,
        state: snapshot.state,
    };
    if let Err(reason) = command.validate_for(&target) {
        let receipt = CommandReceipt::Rejected {
            command_id: command.command_id.clone(),
            reason,
        };
        append_body(
            summary,
            ledger,
            LiveEventBody::ControlAccepted(receipt.clone()),
            subscribers,
        )
        .await?;
        return Ok(receipt);
    }
    let entry = ledger
        .append_fresh_command(&command, handoff)
        .await
        .map_err(live_error)?;
    if matches!(entry.receipt, CommandReceipt::Accepted { .. }) {
        append_body(
            summary,
            ledger,
            LiveEventBody::ControlAccepted(entry.receipt.clone()),
            subscribers,
        )
        .await?;
    }
    Ok(entry.receipt)
}

/// The refusal code of a command whose wait outlived the turn budget; the dispatch itself is
/// never cancelled by it.
const BUDGET_EXPIRED_REFUSAL: &str = "turn_budget_expired";

pub(super) async fn apply_command(
    command: LiveCommand,
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    control: &ControlExecutor,
    normalizer: &EventNormalizer,
    runtime: &mut CommandRuntime<'_>,
    mut clock: Option<&mut TurnBudgetClock>,
) -> Result<CommandReceipt, LiveError> {
    let existing = ledger.command(&command).await.map_err(live_error)?;
    if existing.is_some()
        && ledger
            .fresh_handoff(&command)
            .await
            .map_err(live_error)?
            .is_some()
    {
        return Err(LiveError::unavailable(
            "fresh_handoff_pending",
            "the command belongs to a fresh replacement and cannot be dispatched to this session",
        ));
    }
    let recovering = existing.as_ref().is_some_and(|entry| {
        control.supports_identity_safe_dispatch()
            && entry.dispatch_identity == Some(1)
            && matches!(
                entry.receipt,
                CommandReceipt::Duplicate {
                    prior_outcome: None,
                    ..
                }
            )
            && matches!(
                command.body,
                LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
            )
    });
    if let Some(existing) = &existing {
        if !recovering {
            return Ok(existing.receipt.clone());
        }
    }
    let snapshot = summary.read().map_err(unavailable)?.clone();
    let target = LiveCommandTarget {
        session_id: snapshot.session_id,
        epoch: snapshot.epoch,
        event_head: snapshot.event_head,
        state: snapshot.state,
    };
    if let Err(reason) = command.validate_for(&target).or_else(|reason| {
        if recovering && snapshot.state != LiveSessionState::Ended {
            Ok(())
        } else {
            Err(reason)
        }
    }) {
        let receipt = CommandReceipt::Rejected {
            command_id: command.command_id.clone(),
            reason,
        };
        append_body(
            summary,
            ledger,
            LiveEventBody::ControlAccepted(receipt.clone()),
            runtime.subscribers,
        )
        .await?;
        return Ok(receipt);
    }
    let journal = if let Some(existing) = existing {
        existing
    } else {
        let journal = ledger.append_command(&command).await.map_err(live_error)?;
        if matches!(journal.receipt, CommandReceipt::Duplicate { .. }) {
            return Ok(journal.receipt);
        }
        append_body(
            summary,
            ledger,
            LiveEventBody::ControlAccepted(journal.receipt.clone()),
            runtime.subscribers,
        )
        .await?;
        journal
    };
    // A starting-turn command arms the declared budget at acceptance —
    // after preflight validation and durable journaling, before the awaited
    // dispatch — so the initial journaled dispatch and its correlated reply
    // are bounded by the deadline exactly like every later turn wait.
    // Rejected preflight commands and replayed duplicates return above
    // without touching the clock; an already-armed clock is never re-armed,
    // so follow-ups of one turn share the turn's single deadline.
    let starts_turn = matches!(
        command.body,
        LiveCommandBody::Prompt { .. } | LiveCommandBody::DecideApproval { .. }
    );
    if starts_turn {
        if let Some(clock) = clock.as_mut() {
            clock.arm();
        }
    }
    // The declared per-turn budget stays effective while a command awaits
    // its backend: a running-state command's correlated RPC reply
    // (Steer/Checkpoint/Abort answer only from a `Running` turn) and a
    // starting-turn command's initial dispatch alike. DecidePermission is
    // deliberately not bounded here: it resolves a `RequiresAction` wait,
    // and cancellation waits only for `Running`.
    // A queued stop ends the wait the same way: the stop's own teardown
    // then shuts the backend the command was dispatched to.
    let deadline_bounded = snapshot.state == LiveSessionState::Running || starts_turn;
    let remaining = clock
        .as_ref()
        .and_then(|clock| clock.remaining())
        .filter(|_| deadline_bounded);
    let expiry = async {
        match remaining {
            Some(remaining) => tokio::time::sleep(remaining).await,
            None => std::future::pending().await,
        }
    };
    let mut stopping = runtime.stopping.clone();
    let applied = tokio::select! {
        biased;
        Ok(_) = stopping.wait_for(|stopping| *stopping) => Err(LiveError::unavailable(
            "session_stopping",
            "the session is stopping",
        )),
        () = expiry => Err(LiveError::unavailable(
            BUDGET_EXPIRED_REFUSAL,
            "the turn budget expired before the command applied",
        )),
        applied = control.apply_identified(&command, snapshot.state) => applied,
    };
    let applied = match applied {
        Ok(Some(effect)) => Ok(effect),
        Ok(None) => {
            tracing::error!(
                "odind: live-command-unsettled session={} command={}",
                command.session_id,
                command.command_id
            );
            return Ok(CommandReceipt::Duplicate {
                command_id: command.command_id.clone(),
                prior_outcome: None,
            });
        }
        Err(error)
            if matches!(&error, LiveError::Unavailable { code, .. } if code != BUDGET_EXPIRED_REFUSAL)
                && matches!(
                    command.body,
                    LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
                ) =>
        {
            tracing::error!(
                "odind: live-command-dispatch-unresolved session={} command={} error={error}",
                command.session_id,
                command.command_id
            );
            return Err(error);
        }
        Err(error) => Err(error),
    };
    // Expiry cancels the WAIT, never the dispatched command. For a
    // running-state command the observation below runs the budget's own
    // give-up through the shared abort seam; for a starting-turn command
    // that expired before the session entered Running, the dispatch
    // outcome is unknown and `expired_start` reconciles it below.
    let expired_start = starts_turn
        && snapshot.state != LiveSessionState::Running
        && matches!(
            &applied,
            Err(LiveError::Unavailable { code, .. }) if code == BUDGET_EXPIRED_REFUSAL
        );
    let outcome = match applied {
        Ok(mut effect) => {
            if effect.reclaim_epoch {
                let epoch = ledger
                    .reclaim(snapshot.session_id)
                    .await
                    .map_err(live_error)?;
                normalizer.set_epoch(epoch)?;
                if let Some(terminal) = runtime.terminal {
                    terminal.set_epoch(epoch).await?;
                }
                let mut current = summary.write().map_err(unavailable)?;
                current.epoch = epoch;
                current.pending_permission_count = 0;
            }
            if let Some(provider) = effect.provider {
                summary.write().map_err(unavailable)?.provider = provider;
            }
            if let Some(model) = effect.model {
                summary.write().map_err(unavailable)?.model = model;
            }
            if let LiveCommandBody::DecidePermission {
                request_id,
                decision,
            } = &command.body
            {
                append_body(
                    summary,
                    ledger,
                    LiveEventBody::PermissionResolved(odin_domain::huginn::PermissionResolution {
                        request_id: request_id.clone(),
                        command_id: command.command_id.clone(),
                        decision: *decision,
                    }),
                    runtime.subscribers,
                )
                .await?;
                if summary
                    .read()
                    .map_err(unavailable)?
                    .pending_permission_count
                    > 0
                {
                    effect.state = Some(LiveSessionState::RequiresAction);
                }
            }
            if let Some(next) = effect.state {
                let previous = summary.read().map_err(unavailable)?.state;
                append_body(
                    summary,
                    ledger,
                    LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous,
                        current: next,
                        reason: Some(format!("control:{:?}", command.body.kind())),
                    }),
                    runtime.subscribers,
                )
                .await?;
                normalizer.set_session_state(next)?;
            }
            // A terminating control already stopped the backend bridge as part
            // of the command; finish the local teardown exactly once before
            // the outcome is journaled so a failed teardown never records
            // Applied.
            let mut teardown_error = None;
            if effect.terminate {
                runtime.teardown.bridge_stopped = true;
                if let Some(terminal) = runtime.terminal {
                    if !runtime.teardown.pane_terminated {
                        match terminal.terminate_pane().await {
                            Ok(()) => runtime.teardown.pane_terminated = true,
                            Err(error) => teardown_error = Some(error),
                        }
                    }
                    remove_capture_once(terminal, runtime.teardown, &command.session_id);
                }
            }
            if let Some(error) = teardown_error {
                CommandOutcome::Failed {
                    command_id: command.command_id.clone(),
                    error: CommandFailure {
                        code: "terminate_failed".to_owned(),
                        message: error.to_string(),
                        retryable: matches!(error, LiveError::Unavailable { .. }),
                    },
                }
            } else {
                CommandOutcome::Applied {
                    command_id: command.command_id.clone(),
                }
            }
        }
        Err(error) => CommandOutcome::Failed {
            command_id: command.command_id.clone(),
            error: CommandFailure {
                code: "control_failed".to_owned(),
                message: error.to_string(),
                retryable: matches!(error, LiveError::Unavailable { .. }),
            },
        },
    };
    ledger
        .complete_command(command.command_id.clone(), outcome.clone())
        .await
        .map_err(live_error)?;
    if let LiveCommandBody::SetModel {
        provider,
        model,
        route: Some(decision),
    } = &command.body
    {
        let mut decision = decision.clone();
        if let CommandOutcome::Failed { error, .. } = &outcome {
            decision.refusal = Some(error.message.clone());
        }
        let applied =
            matches!(&outcome, CommandOutcome::Applied { .. }) && decision.refusal.is_none();
        append_body(
            summary,
            ledger,
            LiveEventBody::ModelRouted(odin_domain::huginn::ModelRouted {
                command_id: command.command_id.clone(),
                provider: provider.to_string(),
                model: model.to_string(),
                decision,
                applied,
            }),
            runtime.subscribers,
        )
        .await?;
    }
    append_body(
        summary,
        ledger,
        LiveEventBody::ControlCompleted(outcome),
        runtime.subscribers,
    )
    .await?;
    if expired_start {
        // Reconciliation of the uncertain dispatch: the wire write may
        // already have been accepted, so the child can start the turn after
        // our timeout. Cancel bounded through the shared abort seam (a
        // child with no live turn answers promptly; the bound only fences
        // a child that never answers), disarm this episode for good, and
        // journal the typed failure terminal — Failed, never Idle — so a
        // late-started turn's frames can never reopen a live turn outside
        // the declared budget. The retryable command failure never
        // re-applies its effect on replay: the journaled command row is
        // complete, and recovery advances the epoch before new work.
        if let Some(clock) = clock.as_mut() {
            clock.give_up();
        }
        let cancellation_outcome = match super::cancel_current_turn(control, snapshot.state).await {
            Ok(()) => "the host cancellation confirmed".to_owned(),
            Err(cause) => cause,
        };
        let budget_seconds = clock
            .as_ref()
            .map(|clock| clock.budget.as_secs())
            .unwrap_or_default();
        append_body(
            summary,
            ledger,
            LiveEventBody::Error(SessionError {
                code: "turn_budget_expired".to_owned(),
                message: format!(
                    "the turn exceeded the declared turn budget of {budget_seconds}s before \
                     its dispatch completed; the dispatch outcome is unknown and \
                     {cancellation_outcome}"
                ),
                retryable: true,
                error_status: None,
            }),
            runtime.subscribers,
        )
        .await?;
        normalizer.set_session_state(LiveSessionState::Failed)?;
    }
    if recovering {
        return Ok(ledger
            .command(&command)
            .await
            .map_err(live_error)?
            .expect("recovered command remains journaled")
            .receipt);
    }
    Ok(journal.receipt)
}

pub(super) async fn subscribe(
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    after: EventSeq,
    subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>,
) -> Result<LiveEventStream, LiveError> {
    let session_id = summary.read().map_err(unavailable)?.session_id;
    let head = ledger.head(session_id).await.map_err(live_error)?;
    let (sender, receiver) = mpsc::channel(SUBSCRIPTION_CAPACITY);
    subscribers.push(sender);
    let mut cursor = after;
    let mut events = Vec::new();
    while cursor < head {
        let page = ledger
            .history(HistoryQuery {
                session_id,
                after: cursor,
                limit: REPLAY_PAGE_EVENTS,
            })
            .await
            .map_err(live_error)?;
        if page.events.is_empty() {
            break;
        }
        cursor = page.next_after;
        events.extend(
            page.events
                .into_iter()
                .filter(|event| event.sequence <= head),
        );
    }
    Ok(Box::pin(
        ReplayJoin::open(events, after, head, receiver).replay_then_tail(),
    ))
}

pub(super) async fn append_body(
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    body: LiveEventBody,
    subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>,
) -> Result<LiveEvent, LiveError> {
    let snapshot = summary.read().map_err(unavailable)?.clone();
    let event = ledger
        .append(
            snapshot.epoch,
            NewLiveEvent {
                session_id: snapshot.session_id,
                event_id: EventId::new(format!("event:{}", Uuid::new_v4())).map_err(unavailable)?,
                occurred_at: OffsetDateTime::now_utc(),
                body: body.clone(),
            },
        )
        .await
        .map_err(live_error)?;
    {
        let mut summary = summary.write().map_err(unavailable)?;
        summary.event_head = event.sequence;
        summary.updated_at = event.occurred_at;
        let previous = summary.state;
        match body {
            LiveEventBody::SessionStateChanged(change) => summary.state = change.current,
            LiveEventBody::PermissionRequested(_) => {
                summary.pending_permission_count =
                    summary.pending_permission_count.saturating_add(1)
            }
            LiveEventBody::PermissionResolved(_) => {
                summary.pending_permission_count =
                    summary.pending_permission_count.saturating_sub(1)
            }
            LiveEventBody::TerminalSnapshot(reference) => {
                summary.terminal_head = reference.sequence
            }
            LiveEventBody::TerminalDelta(reference) => summary.terminal_head = reference.sequence,
            LiveEventBody::SessionClosed(_) => summary.state = LiveSessionState::Ended,
            LiveEventBody::Error(_) => summary.state = LiveSessionState::Failed,
            _ => {}
        }
        if summary.state == LiveSessionState::Failed {
            if previous != LiveSessionState::Failed {
                summary.failed_at = Some(event.occurred_at);
            }
        } else {
            summary.failed_at = None;
        }
    }
    publish(event.clone(), subscribers);
    Ok(event)
}
