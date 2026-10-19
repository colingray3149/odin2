//! Bounded turn-boundary rollover: measured thresholds, single-flight
//! driver, durable brief artifact, one journaled reinjection prompt,
//! and the measured usage artifact.

use super::*;

impl Shared {
    /// Pump-side note of one observed `agent_end` frame: records the measured
    /// watermark of the settled turn and arms the single-flight rollover when
    /// the declared threshold and settled-turn spacing hold. The measurement
    /// is recorded whether or not a rollover policy is configured — the
    /// live control seam bounds dispatch against it — and the trigger
    /// remains config-gated exactly as before. Cheap and non-blocking; the
    /// authoritative decision runs later under the lifecycle lock.
    pub(super) fn note_session_turn(self: &Arc<Self>, value: &Value) {
        if !crate::live::rollover::terminal_agent_end(value) {
            return;
        }
        let usage = crate::live::rollover::RolloverUsage::extract(value);
        self.journal_turn_usage(usage.as_ref());
        let fire = {
            let Ok(mut guard) = shared_lock(&self.rollover, "rollover") else {
                return;
            };
            guard.settled_turns = guard.settled_turns.saturating_add(1);
            if let Some(measurement) = guard.measuring.as_mut() {
                measurement.settled_turns_seen = measurement.settled_turns_seen.saturating_add(1);
            }
            guard.last_usage = usage;
            if let Some(usage) = usage {
                guard.watermark = usage.watermark();
            }
            guard
                .config
                .as_ref()
                .map(|config| config.policy().threshold_tokens)
                .is_some_and(|threshold| {
                    !guard.busy
                        && guard.measuring.is_none()
                        && guard.watermark >= threshold
                        && guard.settled_turns >= crate::live::rollover::ROLLOVER_MIN_SETTLED_TURNS
                })
        };
        self.rollover_wake.notify_one();
        if fire {
            let shared = Arc::clone(self);
            drop(tokio::spawn(async move {
                shared.run_rollover().await;
            }));
        }
    }

    /// Pump-side note of one `auto_compaction_end` frame: the compacted
    /// session starts a new context epoch.
    pub(super) fn open_context_epoch(&self) {
        if let Ok(mut guard) = shared_lock(&self.rollover, "rollover") {
            guard.context_epoch = guard.context_epoch.wrapping_add(1);
        }
    }

    /// One `odind: session-turn` line per settled turn: the turn's last
    /// provider request in the provider's own counts (uncached input, input
    /// served from its prompt cache) beside the size of the granted tool
    /// definitions, the most a request can list.
    fn journal_turn_usage(&self, usage: Option<&crate::live::rollover::RolloverUsage>) {
        let count = |value: Option<u64>| value.map_or_else(|| "none".to_owned(), |n| n.to_string());
        let policy = &self.operation_binding.policy;
        tracing::debug!(
            "odind: session-turn seat={} lane={} capsule={} granted_tools={} granted_bytes={} \
             input_tokens={} cached_tokens={} cache_write_tokens={} output_tokens={}",
            policy.seat_id,
            policy.lane_id,
            self.operation_binding.capsule_id,
            self.admitted_host_tools.len(),
            self.listing_bytes.load(Ordering::Relaxed),
            count(usage.and_then(|usage| usage.input_tokens)),
            count(usage.and_then(|usage| usage.cache_read_tokens)),
            count(usage.and_then(|usage| usage.cache_write_tokens)),
            count(usage.and_then(|usage| usage.output_tokens)),
        );
    }

    /// One bounded rollover attempt, single-flighted. Failures are journaled
    /// as `rollover_failed` live events; the busy guard always clears.
    pub(super) async fn run_rollover(self: &Arc<Self>) {
        let armed = {
            let Ok(mut guard) = shared_lock(&self.rollover, "rollover") else {
                return;
            };
            if guard.busy || guard.config.is_none() {
                false
            } else {
                guard.busy = true;
                true
            }
        };
        if !armed {
            return;
        }
        if let Err(detail) = self.rollover_once().await {
            let _ = self
                .append_rollover_event("rollover_failed", json!({ "error": detail }))
                .await;
        }
        if let Ok(mut guard) = shared_lock(&self.rollover, "rollover") {
            guard.busy = false;
            guard.measuring = None;
        }
    }

    /// The full threshold rollover: turn-boundary decision (re-checked
    /// authoritatively under the gate by the shared executor), then the
    /// bounded settle wait and the measured usage artifact.
    async fn rollover_once(&self) -> Result<(), String> {
        use crate::live::rollover;
        let (config, watermark, settled_turns) = {
            let guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| error.to_string())?;
            match guard.config.as_ref() {
                Some(config) => (config.clone(), guard.watermark, guard.settled_turns),
                None => return Ok(()),
            }
        };
        let policy = config.policy();
        // Turn-boundary conditions; the executor re-checks them under the
        // lifecycle gate before anything moves.
        if watermark < policy.threshold_tokens
            || settled_turns < rollover::ROLLOVER_MIN_SETTLED_TURNS
        {
            return Ok(());
        }
        match self.status() {
            Ok(BridgeStatus::Ready) => {}
            Ok(_) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
        if shared_lock(&self.correlation, "correlation")
            .map_err(|error| error.to_string())?
            .active_mutating()
            .is_some()
        {
            return Ok(());
        }
        let executed = self
            .execute_rollover(
                &RolloverTrigger::Threshold {
                    pre_watermark_tokens: watermark,
                },
                None,
            )
            .await?;

        // Bounded wait for the reinjection turn to settle, then the measured
        // usage record. The lifecycle gate is NOT held here: operator
        // prompts queue behind the reinjection in the child, exactly as
        // journaled.
        let (settled, usage) = self
            .wait_reinjection_settle(rollover::ROLLOVER_REINJECTION_SETTLE_BUDGET)
            .await;
        let measurement = shared_lock(&self.rollover, "rollover")
            .ok()
            .and_then(|guard| guard.measuring.clone());
        let measured_watermark = measurement
            .as_ref()
            .map(|m| m.pre_watermark)
            .unwrap_or(watermark);
        let measured_threshold = measurement
            .as_ref()
            .map(|m| m.threshold_tokens)
            .unwrap_or(executed.threshold_tokens);
        let measured_epoch = measurement
            .as_ref()
            .map(|m| m.epoch_before)
            .unwrap_or(executed.epoch_before);
        let measured_brief_id = measurement
            .as_ref()
            .map(|m| m.brief_artifact_id.clone())
            .unwrap_or_else(|| executed.brief_artifact_id.clone());
        let measured_brief_digest = measurement
            .as_ref()
            .map(|m| m.brief_digest.clone())
            .unwrap_or_else(|| executed.brief_hex.clone());
        let measured_command = measurement
            .as_ref()
            .and_then(|m| m.command_id.clone())
            .unwrap_or(executed.reinjection_command);
        let usage_value = json!({
            "schema": "odin.rollover-usage.v1",
            "session_id": executed.session_id,
            "epoch_before": measured_epoch,
            "epoch_after": executed.epoch_after,
            "trigger": {
                "kind": "threshold",
                "threshold_tokens": measured_threshold,
                "pre_rollover_watermark_tokens": measured_watermark,
            },
            "brief_artifact": {
                "media_type": rollover::ROLLOVER_MEDIA_TYPE_BRIEF,
                "id": measured_brief_id,
                "digest": measured_brief_digest,
            },
            "reinjection": {
                "command_id": measured_command,
                "settled": settled,
                "observed_usage": usage,
            },
            "recorded_at_ms": unix_ms(now_utc()),
        });
        self.record_usage_artifact(usage_value).await
    }

    /// The shared canonical rollover executor — the ONE durable-rows brief
    /// builder, ONE planned fresh-context respawn (same session id,
    /// epoch + 1, NEW empty conversation: every session selector stripped,
    /// so the pinned harness's default launch persists a fresh transcript),
    /// an optional journaled model selection re-asserted after the respawn
    /// and BEFORE the reinjection, and ONE journaled reinjection prompt
    /// carrying the bounded brief. The threshold trigger measures the
    /// reinjection turn and awaits it; the context-refusal trigger returns
    /// after the journaled dispatch admission, so the caller never holds a
    /// turn-length await.
    async fn execute_rollover(
        &self,
        trigger: &RolloverTrigger,
        selected_model: Option<(String, String)>,
    ) -> Result<ExecutedRollover, String> {
        use crate::live::rollover;
        let (config, children) = {
            let guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| error.to_string())?;
            match (guard.config.as_ref(), guard.children.as_ref()) {
                (Some(config), Some(children)) => (config.clone(), Arc::clone(children)),
                _ => {
                    return Err(
                        "rollover configured without a delegated-children state source".to_owned(),
                    )
                }
            }
        };
        let policy = config.policy();
        let _lifecycle = self.lifecycle.lock().await;
        // Re-checked under the gate: a mutating transition that slipped in
        // ahead of the lock wins, and a rollover never runs beside one.
        match self.status() {
            Ok(BridgeStatus::Ready) => {}
            Ok(_) => return Err("the bridge is not ready for a rollover".to_owned()),
            Err(error) => return Err(error.to_string()),
        }
        if shared_lock(&self.correlation, "correlation")
            .map_err(|error| error.to_string())?
            .active_mutating()
            .is_some()
        {
            return Err("another mutating transition is in flight".to_owned());
        }
        let binding = self.binding_snapshot().map_err(|error| error.to_string())?;
        let epoch_before = binding.epoch;
        let assignment = children
            .assignment(&binding.session_id)
            .await
            .map_err(|detail| format!("delegated-assignment read failed: {detail}"))?;
        let children = children
            .children(&binding.session_id, rollover::ROLLOVER_CHILDREN_CAP)
            .await
            .map_err(|detail| format!("delegated-children state read failed: {detail}"))?;

        // Durable rows only: identity, task plan/acceptance, pending
        // approvals, and the bounded event walk.
        let observed_watermark = trigger.observed_watermark();
        let session_id = binding.session_id.clone();
        let run_id = binding.run_id.clone();
        let seat_id = binding_seat(&binding);
        let project_id = binding_project(&binding);
        let lane_id = binding.lane_id.to_string();
        let inputs = self
            .ledger_op(move |ledger| {
                let row = ledger.live_session(&session_id).map_err(|error| {
                    LedgerError::invalid_data_caused_by("live session load failed", error)
                })?;
                let plan = match ledger.plan(&run_id).map_err(|error| {
                    LedgerError::invalid_data_caused_by("plan load failed", error)
                })? {
                    Some(plan) => {
                        let accepted = ledger.plan_is_accepted(&run_id).map_err(|error| {
                            LedgerError::invalid_data_caused_by(
                                "plan acceptance load failed",
                                error,
                            )
                        })?;
                        Some(rollover::RolloverPlanRecord {
                            revision: plan.revision,
                            objective: plan.objective.clone(),
                            todos: plan
                                .todos
                                .iter()
                                .map(|todo| {
                                    json!({
                                        "id": todo.id,
                                        "ordinal": todo.ordinal,
                                        "title": todo.title,
                                        "status": todo.status,
                                    })
                                })
                                .collect(),
                            accepted,
                        })
                    }
                    None => None,
                };
                let pending_approvals = ledger
                    .approvals()
                    .map_err(|error| {
                        LedgerError::invalid_data_caused_by("approval load failed", error)
                    })?
                    .into_iter()
                    .filter(|approval| {
                        matches!(approval.status, odin_domain::ApprovalStatus::Requested)
                            && approval.scope.target_kind == "session"
                            && approval.scope.target_id == session_id.to_string()
                    })
                    .map(|approval| rollover::RolloverPendingApproval {
                        approval_id: approval.approval_id.to_string(),
                        capability_id: approval.scope.capability_id.to_string(),
                        target_kind: approval.scope.target_kind.clone(),
                        target_id: approval.scope.target_id.clone(),
                        issuer: approval.issuer.clone(),
                        requested_at_ms: unix_ms(approval.requested_at) as i64,
                        expires_at_ms: unix_ms(approval.expires_at) as i64,
                    })
                    .collect::<Vec<_>>();
                let events =
                    live_history_tail(ledger, &session_id, rollover::ROLLOVER_HISTORY_WALK_CAP)
                        .map_err(|error| {
                            LedgerError::invalid_data_caused_by(
                                "live history tail load failed",
                                error,
                            )
                        })?
                        .into_iter()
                        .map(|event| event.body)
                        .collect::<Vec<_>>();
                Ok(rollover::RolloverBriefInputs {
                    session_id: session_id.to_string(),
                    seat_id,
                    project_id,
                    lane_id,
                    provider: manifest_field(&row.manifest, &["provider"]),
                    model: manifest_field(&row.manifest, &["model"]),
                    title: row.title.clone(),
                    epoch_before: row.epoch,
                    observed_watermark,
                    threshold_tokens: policy.threshold_tokens,
                    plan,
                    assignment,
                    children,
                    pending_approvals,
                    events,
                })
            })
            .await
            .map_err(|error: BridgeError| error.to_string())?;

        let (_brief_value, brief_bytes) = rollover::render_brief(&inputs, &policy)?;
        let brief_digest = Digest::hash(&brief_bytes);
        let brief_hex = digest_hex(&brief_digest);
        let brief_relative = format!("{}/{}", &brief_hex[..2], brief_hex);
        let brief_path = self.artifact_root.join(&brief_relative);
        let brief_write = brief_bytes.clone();
        tokio::task::spawn_blocking(move || write_content_addressed(&brief_path, &brief_write))
            .await
            .map_err(|error| format!("rollover brief writer failed: {error}"))?
            .map_err(|error| error.to_string())?;
        let registration_media = brief_bytes.clone();
        let registration_relative = brief_relative.clone();
        let brief_metadata = self
            .ledger_op(move |ledger| {
                ledger
                    .register_artifact(ArtifactRegistration {
                        bytes: &registration_media,
                        media_type: rollover::ROLLOVER_MEDIA_TYPE_BRIEF,
                        storage_path: &registration_relative,
                        retention: RetentionClass::Pinned,
                        created_at: now_utc(),
                    })
                    .map_err(|error| {
                        LedgerError::invalid_data_caused_by(
                            "rollover brief artifact registration failed",
                            error,
                        )
                    })
            })
            .await
            .map_err(|error: BridgeError| error.to_string())?;

        // Watermark resets at rollover start; the threshold trigger's own
        // reinjection measurement re-arms accounting for the new
        // incarnation. The refusal trigger records no measurement: the
        // fresh incarnation's turns settle on their own.
        let measure = matches!(trigger, RolloverTrigger::Threshold { .. });
        {
            let mut guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| error.to_string())?;
            guard.watermark = 0;
            guard.settled_turns = 0;
            guard.context_epoch = guard.context_epoch.wrapping_add(1);
            guard.measuring = measure.then(|| RolloverMeasurement {
                pre_watermark: trigger.pre_watermark_tokens(),
                threshold_tokens: policy.threshold_tokens,
                epoch_before,
                brief_digest: brief_hex.clone(),
                brief_artifact_id: brief_metadata.artifact_id.to_string(),
                command_id: None,
                settled_turns_seen: 0,
            });
        }
        self.append_rollover_event(
            "rollover_triggered",
            match trigger {
                RolloverTrigger::Threshold {
                    pre_watermark_tokens,
                } => json!({
                    "trigger": "threshold",
                    "epoch_before": epoch_before,
                    "watermark_tokens": pre_watermark_tokens,
                    "threshold_tokens": policy.threshold_tokens,
                    "brief_digest": brief_hex.clone(),
                }),
                RolloverTrigger::ContextRefusal { event } => json!({
                    "trigger": "context_refusal",
                    "refusal_event": event,
                    "epoch_before": epoch_before,
                    "brief_digest": brief_hex.clone(),
                }),
            },
        )
        .await
        .map_err(|error| error.to_string())?;

        // Respawn through the shared recover mechanics: same session id,
        // epoch + 1, identity-checked child — a FRESH conversation (new
        // empty context), never a transcript resume of the oversized one;
        // no tab, no delegated child is touched, so background jobs survive.
        let report = self
            .recover_sequence(super::recovery::RecoverMode::FreshContext)
            .await
            .map_err(|error| format!("rollover respawn failed: {error}"))?;
        let epoch_after = report.epoch;

        // The fresh carrier composes from the launch manifest: a journaled
        // model selection is re-asserted AFTER the respawn and BEFORE the
        // reinjection turn, so the incarnation's first turn — the continue
        // order — runs the selected model and its context budget, never
        // the launch pair with a correction after the turn was already
        // admitted.
        if let Some((provider, model)) = &selected_model {
            self.execute_already_gated(
                "set_model",
                json!({ "type": "set_model", "provider": provider, "modelId": model }),
                InFlightKind::Mutating,
            )
            .await
            .map_err(|error| format!("rollover model re-assert failed: {error}"))?;
        }

        // ONE journaled reinjection turn: a delegated worker's fresh
        // incarnation receives the brief (its original assignment beside
        // the bounded progress summary) AS its next work order — the same
        // worker resuming the interrupted unit, never a context sink left
        // idle after an absorption acknowledgement. A session that is
        // nobody's delegated child keeps the absorb-only carrier: its
        // successor awaits its next request instead of improvising work.
        let header = format!(
            "{} session={} epoch={}->{} trigger={}]",
            rollover::ROLLOVER_PROMPT_MARKER,
            binding.session_id,
            epoch_before,
            epoch_after,
            trigger.kind(),
        );
        let brief_text = String::from_utf8_lossy(&brief_bytes);
        let message = if inputs.assignment.is_some() {
            rollover::continuation_prompt(&header, &brief_text)
        } else {
            rollover::continuity_prompt(&header, &brief_text)
        };
        // The refusal trigger returns at the journaled dispatch admission,
        // so its reinjection owns no waiter: Observed delivery keeps a
        // rejected or mismatched correlated response annotated on the
        // frame for the session journal — typed evidence the actor
        // normalizes — instead of an error sent to a dropped receiver.
        // The threshold trigger awaits its waiter below and keeps Awaited.
        let delivery = if measure {
            ReplyDelivery::Awaited
        } else {
            ReplyDelivery::Observed
        };
        let dispatched = self
            .dispatch(
                "prompt",
                json!({ "type": "prompt", "message": message }),
                InFlightKind::Mutating,
                delivery,
            )
            .await
            .map_err(|error| format!("rollover reinjection dispatch failed: {error}"))?;
        let reinjection_command = dispatched.command_id.to_string();
        if measure {
            if let Ok(mut guard) = shared_lock(&self.rollover, "rollover") {
                if let Some(measurement) = guard.measuring.as_mut() {
                    measurement.command_id = Some(reinjection_command.clone());
                }
            }
        }
        if measure {
            drop(_lifecycle);
            Shared::await_dispatched(dispatched)
                .await
                .map_err(|error| format!("rollover reinjection failed: {error}"))?;
        }
        Ok(ExecutedRollover {
            session_id: binding.session_id.to_string(),
            epoch_before,
            epoch_after,
            brief_hex,
            brief_artifact_id: brief_metadata.artifact_id.to_string(),
            reinjection_command,
            threshold_tokens: policy.threshold_tokens,
        })
    }

    /// The typed context-refusal rollover entry: a planned fresh-context
    /// respawn of THIS session answering a typed provider context refusal.
    /// Declared rollover configuration is required; single-flighted with the
    /// threshold driver; `rollover_completed` journaled; no usage settle is
    /// held. `selected_model` — a journaled model choice that differs from
    /// the launch pair — is re-asserted after the respawn and before the
    /// reinjection turn. Returns the fresh epoch.
    pub(super) async fn rollover_context_refusal(
        self: &Arc<Self>,
        refusal_event: u64,
        selected_model: Option<(String, String)>,
    ) -> Result<i64, BridgeError> {
        {
            let mut guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| BridgeError::Config {
                    detail: error.to_string(),
                })?;
            if guard.config.is_none() {
                return Err(BridgeError::Config {
                    detail: "context-refusal rollover needs the session's declared \
                             [live.rollover] configuration"
                        .to_owned(),
                });
            }
            if guard.busy {
                return Err(BridgeError::Config {
                    detail: "another rollover is in flight".to_owned(),
                });
            }
            guard.busy = true;
        }
        let _busy = RolloverBusyGuard {
            shared: Arc::clone(self),
        };
        match self.status() {
            Ok(BridgeStatus::Ready) => {}
            Ok(status) => {
                return Err(BridgeError::NotReady {
                    state: format!("{status:?}"),
                })
            }
            Err(error) => return Err(error),
        }
        if shared_lock(&self.correlation, "correlation")
            .map_err(|error| BridgeError::Config {
                detail: error.to_string(),
            })?
            .active_mutating()
            .is_some()
        {
            return Err(BridgeError::Config {
                detail: "another mutating transition is in flight".to_owned(),
            });
        }
        let executed = self
            .execute_rollover(
                &RolloverTrigger::ContextRefusal {
                    event: refusal_event,
                },
                selected_model,
            )
            .await
            .map_err(|detail| BridgeError::ProcessDown { detail })?;
        self.append_rollover_event(
            "rollover_completed",
            json!({
                "trigger": "context_refusal",
                "refusal_event": refusal_event,
                "epoch_before": executed.epoch_before,
                "epoch_after": executed.epoch_after,
                "brief_digest": executed.brief_hex,
            }),
        )
        .await?;
        Ok(executed.epoch_after)
    }

    /// Content-addresses and registers the measured usage artifact and
    /// journals `rollover_completed`.
    async fn record_usage_artifact(&self, usage_value: Value) -> Result<(), String> {
        use crate::live::rollover;
        let usage_bytes = serde_json::to_vec(&usage_value)
            .map_err(|error| format!("rollover usage render failed: {error}"))?;
        let usage_hex = digest_hex(&Digest::hash(&usage_bytes));
        let usage_relative = format!("{}/{}", &usage_hex[..2], usage_hex);
        let usage_path = self.artifact_root.join(&usage_relative);
        let usage_write = usage_bytes.clone();
        tokio::task::spawn_blocking(move || write_content_addressed(&usage_path, &usage_write))
            .await
            .map_err(|error| format!("rollover usage writer failed: {error}"))?
            .map_err(|error| error.to_string())?;
        let usage_media = usage_bytes;
        let usage_storage = usage_relative.clone();
        let usage_hex_event = usage_hex.clone();
        self.ledger_op(move |ledger| {
            ledger
                .register_artifact(ArtifactRegistration {
                    bytes: &usage_media,
                    media_type: rollover::ROLLOVER_MEDIA_TYPE_USAGE,
                    storage_path: &usage_storage,
                    retention: RetentionClass::Pinned,
                    created_at: now_utc(),
                })
                .map_err(|error| {
                    LedgerError::invalid_data_caused_by(
                        "rollover usage artifact registration failed",
                        error,
                    )
                })
        })
        .await
        .map_err(|error: BridgeError| error.to_string())?;
        let (epoch_before, epoch_after, settled) = (
            usage_value["epoch_before"].as_i64().unwrap_or_default(),
            usage_value["epoch_after"].as_i64().unwrap_or_default(),
            usage_value["reinjection"]["settled"]
                .as_bool()
                .unwrap_or(false),
        );
        self.append_rollover_event(
            "rollover_completed",
            json!({
                "trigger": "threshold",
                "epoch_before": epoch_before,
                "epoch_after": epoch_after,
                "settled": settled,
                "usage_digest": usage_hex_event,
            }),
        )
        .await
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Bounded wait for the measured settle of the reinjection turn. Returns
    /// `(settled, usage)`; `settled` is false only on budget expiry or lost
    /// measurement, never fabricated.
    async fn wait_reinjection_settle(
        &self,
        budget: Duration,
    ) -> (bool, Option<crate::live::rollover::RolloverUsage>) {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            {
                let Ok(guard) = shared_lock(&self.rollover, "rollover") else {
                    return (false, None);
                };
                match &guard.measuring {
                    Some(measurement) if measurement.settled_turns_seen >= 1 => {
                        return (true, guard.last_usage)
                    }
                    Some(_) => {}
                    None => return (false, None),
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return (false, None);
            }
            let _ = tokio::time::timeout(remaining, self.rollover_wake.notified()).await;
        }
    }

    /// Appends one rollover live event (`rollover_triggered`,
    /// `rollover_completed`, `rollover_failed`) to the durable journal.
    async fn append_rollover_event(
        &self,
        kind: &str,
        mut details: Value,
    ) -> Result<(), BridgeError> {
        if let Some(object) = details.as_object_mut() {
            object.insert("kind".to_owned(), json!(kind));
        }
        self.append_event(details).await
    }
}

/// What triggered one rollover: the measured token threshold at a settled
/// turn boundary, or a typed provider context refusal the kernel answers
/// with a fresh incarnation.
pub(super) enum RolloverTrigger {
    Threshold { pre_watermark_tokens: u64 },
    ContextRefusal { event: u64 },
}

impl RolloverTrigger {
    /// The watermark the brief's identity block records; a refused turn
    /// never settled an `agent_end`, so it has none.
    fn observed_watermark(&self) -> Option<u64> {
        match self {
            Self::Threshold {
                pre_watermark_tokens,
            } => Some(*pre_watermark_tokens),
            Self::ContextRefusal { .. } => None,
        }
    }

    fn pre_watermark_tokens(&self) -> u64 {
        match self {
            Self::Threshold {
                pre_watermark_tokens,
            } => *pre_watermark_tokens,
            Self::ContextRefusal { .. } => 0,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Threshold { .. } => "threshold",
            Self::ContextRefusal { .. } => "context_refusal",
        }
    }
}

/// What one executed rollover produced: the identity epochs, the brief's
/// content digest and registered artifact, and the journaled reinjection
/// command.
pub(super) struct ExecutedRollover {
    pub(super) session_id: String,
    pub(super) epoch_before: i64,
    pub(super) epoch_after: i64,
    pub(super) brief_hex: String,
    pub(super) brief_artifact_id: String,
    pub(super) reinjection_command: String,
    pub(super) threshold_tokens: u64,
}

/// Clears the single-flight busy flag when one rollover attempt ends,
/// however it ends.
struct RolloverBusyGuard {
    shared: Arc<Shared>,
}

impl Drop for RolloverBusyGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = shared_lock(&self.shared.rollover, "rollover") {
            guard.busy = false;
        }
    }
}

/// The measured state of one reinjection turn a rollover is accounting.
#[derive(Clone, Debug)]
pub(super) struct RolloverMeasurement {
    pub(super) pre_watermark: u64,
    pub(super) threshold_tokens: u64,
    pub(super) epoch_before: i64,
    pub(super) brief_digest: String,
    pub(super) brief_artifact_id: String,
    pub(super) command_id: Option<String>,
    pub(super) settled_turns_seen: u32,
}

/// Bounded rollover bookkeeping owned by [`Shared`]. `watermark` is only
/// ever a provider-reported total (see
/// [`crate::live::rollover::RolloverUsage`]); `settled_turns` counts
/// terminal turns since the last rollover start; `busy` single-flights the
/// driver; `measuring` spans the reinjection turn so its settle can be
/// awaited.
pub(super) struct RolloverTracker {
    pub(super) config: Option<crate::live::rollover::RolloverRuntimeConfig>,
    pub(super) children: Option<Arc<dyn crate::live::rollover::RolloverChildrenSource>>,
    pub(super) watermark: u64,
    pub(super) settled_turns: u32,
    pub(super) busy: bool,
    pub(super) last_usage: Option<crate::live::rollover::RolloverUsage>,
    pub(super) measuring: Option<RolloverMeasurement>,
    /// Counts the session's context epochs: compactions and rollovers each
    /// open one, so the next turn carries fresh brain context.
    pub(super) context_epoch: u64,
}

impl RolloverTracker {
    /// Disabled tracker: exactly today's no-rollover behavior.
    pub(super) fn new(
        config: Option<crate::live::rollover::RolloverRuntimeConfig>,
        children: Option<Arc<dyn crate::live::rollover::RolloverChildrenSource>>,
    ) -> Self {
        Self {
            config,
            children,
            watermark: 0,
            settled_turns: 0,
            busy: false,
            last_usage: None,
            measuring: None,
            context_epoch: 0,
        }
    }
}

fn binding_seat(binding: &BridgeBinding) -> String {
    binding
        .scope
        .seat
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn binding_project(binding: &BridgeBinding) -> String {
    binding
        .scope
        .project
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
}

/// First non-empty string under any of `keys` of one manifest value.
fn manifest_field(manifest: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = manifest.get(*key).and_then(Value::as_str) {
            if !value.is_empty() {
                return value.to_owned();
            }
        }
    }
    String::new()
}
