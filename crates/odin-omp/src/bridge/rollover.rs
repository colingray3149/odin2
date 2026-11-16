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
            guard.fires()
        };
        self.rollover_wake.notify_one();
        if fire {
            let shared = Arc::clone(self);
            drop(tokio::spawn(async move {
                shared.run_rollover().await;
            }));
        }
    }

    /// Pump-side note of one provider round (`turn_end`) of a pod: its
    /// assistant message's usage is the context it holds now. Crossing the
    /// checkpoint sends ONE steer per context epoch, asking for working notes
    /// while the turn runs on. Seat sessions ignore provider rounds.
    pub(super) fn note_pod_checkpoint(self: &Arc<Self>, value: &Value) {
        let Some(usage) = crate::live::rollover::RolloverUsage::extract(value) else {
            return;
        };
        let percent = {
            let Ok(mut guard) = shared_lock(&self.rollover, "rollover") else {
                return;
            };
            if guard
                .config
                .as_ref()
                .is_none_or(|config| config.pod().is_none())
            {
                return;
            }
            guard.watermark = usage.watermark();
            guard.last_usage = Some(usage);
            let watermark = guard.watermark;
            let epoch = guard.context_epoch;
            let Some(threshold) = guard.effective_threshold() else {
                return;
            };
            if watermark < threshold || guard.checkpoint_epoch == Some(epoch) {
                return;
            }
            guard.checkpoint_epoch = Some(epoch);
            watermark.saturating_mul(100) / guard.card_window.max(1)
        };
        let shared = Arc::clone(self);
        drop(tokio::spawn(async move {
            shared.send_pod_checkpoint(percent).await;
        }));
    }

    /// Sends a pod's checkpoint steer into its running turn, when its rollover
    /// budget still admits the rollover the notes are for. Failures are logged;
    /// the window refusal stays the backstop.
    async fn send_pod_checkpoint(&self, percent: u64) {
        let config = shared_lock(&self.rollover, "rollover")
            .ok()
            .and_then(|guard| guard.config.clone());
        let Some(config) = config else {
            return;
        };
        if let Err(detail) = self.admit_pod_rollover(&config).await {
            tracing::warn!("odind: pod checkpoint not sent: {detail}");
            return;
        }
        let frame = json!({
            "type": "steer",
            "message": crate::live::rollover::pod_checkpoint_prompt(percent),
        });
        let _lifecycle = self.lifecycle.lock().await;
        if let Err(error) = self
            .dispatch(
                "steer",
                frame,
                InFlightKind::Mutating,
                ReplyDelivery::Observed,
            )
            .await
        {
            tracing::warn!("odind: pod checkpoint steer not sent: {error}");
        }
    }

    /// Rollovers this session has begun, counted from the journal:
    /// `rollover_triggered` is written before any respawn, so a crash cannot
    /// reset the count.
    async fn begun_rollovers(&self) -> Result<u32, String> {
        let session = self
            .binding_snapshot()
            .map_err(|error| error.to_string())?
            .session_id;
        self.ledger_op(move |ledger| {
            journaled_rollover_count(ledger, &session, "rollover_triggered")
        })
        .await
        .map_err(|error| error.to_string())
    }

    /// Admits one rollover against a pod's declared budget and reports whether
    /// it is the last one allowed. Seat sessions are never refused here.
    async fn admit_pod_rollover(
        &self,
        config: &crate::live::rollover::RolloverRuntimeConfig,
    ) -> Result<bool, String> {
        match config.pod() {
            Some(pod) => pod.admit(self.begun_rollovers().await?),
            None => Ok(false),
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
        let threshold = {
            let guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| error.to_string())?;
            guard
                .effective_threshold()
                .unwrap_or(policy.threshold_tokens)
        };
        // Turn-boundary conditions; the executor re-checks them under the
        // lifecycle gate before anything moves. The threshold is the
        // selected card's declared fraction when the seat declared one.
        if !config.rolls_at_settled_turns()
            || watermark < threshold
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
        // The bound is tested against the rollover this boundary would
        // complete. The count itself is committed only after that rollover
        // succeeds, so a refused gate or a failed source read cannot
        // advance a supervisor toward a fresh session it has not earned.
        let completed = shared_lock(&self.rollover, "rollover")
            .map_err(|error| error.to_string())?
            .rollovers_completed;
        let prospective = completed.saturating_add(1);
        if policy.fresh_due(prospective) {
            let callback = shared_lock(&self.fresh_bound, "fresh_bound")
                .map_err(|error| error.to_string())?
                .clone()
                .ok_or_else(|| "fresh handoff has no callback".to_owned())?;
            callback(prospective).await?;
            self.append_rollover_event(
                "fresh_handoff_due",
                json!({
                    "completed_rollovers": prospective,
                    "bound": policy.fresh_after_rollovers,
                }),
            )
            .await
            .map_err(|error| error.to_string())?;
            return Ok(());
        }
        let pod_last = self.admit_pod_rollover(&config).await?;
        let executed = self
            .execute_rollover(
                &RolloverTrigger::Threshold {
                    pre_watermark_tokens: watermark,
                },
                None,
                pod_last,
            )
            .await?;
        self.commit_rollover_count().await?;

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
            "recorded_at_ms": unix_ms(OffsetDateTime::now_utc()),
        });
        self.record_usage_artifact(usage_value, measured_epoch, executed.epoch_after, settled)
            .await
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
        pod_last: bool,
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
        let seat_id = binding.seat_id();
        let project_id = binding.project_id();
        let lane_id = binding.lane_id.to_string();
        let inputs = self
            .ledger_op(move |ledger| {
                let row = ledger.live_session(&session_id).map_err(|error| {
                    LedgerError::invalid_data_caused_by("live session load failed", error)
                })?;
                let (plan, pending_approvals) =
                    rollover::durable_rows(ledger, &session_id, &run_id)?;
                let events = live_history_tail(
                    ledger,
                    &session_id,
                    rollover::ROLLOVER_HISTORY_WALK_CAP,
                    DURABLE_HISTORY,
                )
                .map_err(|error| {
                    LedgerError::invalid_data_caused_by("live history tail load failed", error)
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
        let brief_hex = brief_digest.hex();
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
                        created_at: OffsetDateTime::now_utc(),
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
        if let Some(root) = &self.context_trace_root {
            let block = crate::live::context_trace::Block::new(
                "rollover brief",
                &brief_text,
                vec![brief_metadata.artifact_id.to_string()],
            );
            let traced = odin_domain::huginn::LiveSessionId::parse(&binding.session_id.to_string())
                .map_err(|error| error.to_string())
                .and_then(|session| {
                    crate::live::context_trace::record(
                        root,
                        session,
                        crate::live::context_trace::Kind::Rollover,
                        None,
                        &[block],
                    )
                });
            if let Err(error) = traced {
                tracing::warn!("odind: injected context not traced: {error}");
            }
        }
        // A pod resumes its own unit from its notes; a delegated worker resumes
        // its assignment; any other session absorbs the brief and waits.
        let message = match config.pod() {
            Some(pod) => rollover::pod_continuation_prompt(
                &header,
                &brief_text,
                &pod.launch_inputs,
                pod_last,
            ),
            None if inputs.assignment.is_some() => {
                rollover::continuation_prompt(&header, &brief_text)
            }
            None => rollover::continuity_prompt(&header, &brief_text),
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
        let config = {
            let mut guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| BridgeError::Config {
                    detail: error.to_string(),
                })?;
            let Some(config) = guard.config.clone() else {
                return Err(BridgeError::Config {
                    detail: "context-refusal rollover needs the session's declared \
                             [live.rollover] configuration"
                        .to_owned(),
                });
            };
            if guard.busy {
                return Err(BridgeError::Config {
                    detail: "another rollover is in flight".to_owned(),
                });
            }
            guard.busy = true;
            config
        };
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
        let pod_last = self
            .admit_pod_rollover(&config)
            .await
            .map_err(|detail| BridgeError::Config { detail })?;
        let executed = self
            .execute_rollover(
                &RolloverTrigger::ContextRefusal {
                    event: refusal_event,
                },
                selected_model,
                pod_last,
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
    async fn record_usage_artifact(
        &self,
        usage_value: Value,
        epoch_before: i64,
        epoch_after: i64,
        settled: bool,
    ) -> Result<(), String> {
        use crate::live::rollover;
        let usage_bytes = serde_json::to_vec(&usage_value)
            .map_err(|error| format!("rollover usage render failed: {error}"))?;
        let usage_hex = Digest::hash(&usage_bytes).hex();
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
                    created_at: OffsetDateTime::now_utc(),
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

    /// Commits one successful same-session rollover. The in-memory count and
    /// the durable metadata move together; a failed rollover never reaches here.
    async fn commit_rollover_count(&self) -> Result<(), String> {
        let completed = {
            let mut guard =
                shared_lock(&self.rollover, "rollover").map_err(|error| error.to_string())?;
            let completed = guard.rollovers_completed.saturating_add(1);
            guard.rollovers_completed = completed;
            completed
        };
        let session = self
            .binding_snapshot()
            .map_err(|error| error.to_string())?
            .session_id;
        self.ledger_op(move |ledger| write_rollover_count(ledger, &session, completed))
            .await
            .map_err(|error| error.to_string())
    }
}

/// Durable key of the successful same-session rollover count.
pub(super) const ROLLOVER_COUNT_KEY: &str = "rollovers_completed";

/// The count a replacement bridge resumes with. Journaled
/// `rollover_completed` events cover a crash after the usage record and
/// before the counter write. `rollover_failed` is not a completion.
pub(super) fn restored_rollover_count(
    ledger: &Ledger,
    session: &odin_domain::SessionId,
) -> Result<u32, LedgerError> {
    let stored = match ledger.live_metadata(
        session,
        odin_ledger::live::LiveMetadataKind::File,
        ROLLOVER_COUNT_KEY,
    ) {
        Ok(meta) => meta
            .payload
            .get("count")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or(0),
        Err(LedgerError::NotFound { .. }) => 0,
        Err(error) => return Err(error),
    };
    Ok(stored.max(journaled_rollover_count(
        ledger,
        session,
        "rollover_completed",
    )?))
}

fn write_rollover_count(
    ledger: &mut Ledger,
    session: &odin_domain::SessionId,
    count: u32,
) -> Result<(), LedgerError> {
    let payload = json!({ "count": count });
    let kind = odin_ledger::live::LiveMetadataKind::File;
    let now = time::OffsetDateTime::now_utc();
    match ledger.live_metadata(session, kind, ROLLOVER_COUNT_KEY) {
        Ok(existing) => {
            ledger.put_live_metadata(
                session,
                kind,
                ROLLOVER_COUNT_KEY,
                &payload,
                Some(existing.revision),
                now,
            )?;
        }
        Err(LedgerError::NotFound { .. }) => {
            ledger.put_live_metadata(session, kind, ROLLOVER_COUNT_KEY, &payload, None, now)?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn journaled_rollover_count(
    ledger: &Ledger,
    session: &odin_domain::SessionId,
    kind: &str,
) -> Result<u32, LedgerError> {
    let count: i64 = ledger.connection().query_row(
        "SELECT COUNT(*) FROM live_events WHERE session_id=?1 \
         AND json_extract(body_json,'$.kind')=?2",
        [session.to_string(), kind.to_owned()],
        |row| row.get(0),
    )?;
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
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
    /// Context window of the model card the session is running now, and the
    /// lane ceiling that card may spend. The fraction trigger reads these;
    /// a seat with no fraction ignores them.
    pub(super) card_window: u64,
    pub(super) card_ceiling: u64,
    /// Same-session rollovers completed on this incarnation. A declared
    /// fresh bound retires the session once this reaches it.
    pub(super) rollovers_completed: u32,
    pub(super) watermark: u64,
    pub(super) settled_turns: u32,
    pub(super) busy: bool,
    pub(super) last_usage: Option<crate::live::rollover::RolloverUsage>,
    pub(super) measuring: Option<RolloverMeasurement>,
    /// Counts the session's context epochs: compactions and rollovers each
    /// open one, so the next turn carries fresh brain context.
    pub(super) context_epoch: u64,
    /// The context epoch a pod's checkpoint steer was sent in: one per epoch.
    pub(super) checkpoint_epoch: Option<u64>,
}

impl RolloverTracker {
    /// Disabled tracker: exactly today's no-rollover behavior.
    /// `completed` is the durable successful count for this session, zero
    /// on a first launch.
    pub(super) fn new(
        config: Option<crate::live::rollover::RolloverRuntimeConfig>,
        children: Option<Arc<dyn crate::live::rollover::RolloverChildrenSource>>,
        completed: u32,
    ) -> Self {
        Self {
            config,
            children,
            card_window: 0,
            card_ceiling: 0,
            rollovers_completed: completed,
            watermark: 0,
            settled_turns: 0,
            busy: false,
            last_usage: None,
            measuring: None,
            context_epoch: 0,
            checkpoint_epoch: None,
        }
    }
}

impl RolloverTracker {
    /// The watermark this seat fires at for the card it is running now.
    /// A declared fraction is exactly that percent of the card window;
    /// no fraction keeps the absolute watermark.
    pub(super) fn effective_threshold(&self) -> Option<u64> {
        let policy = self.config.as_ref()?.policy();
        if policy.window_fraction.is_some() {
            return policy.threshold_for_window(self.card_window, self.card_ceiling);
        }
        Some(policy.threshold_tokens)
    }

    /// Whether the measured watermark and the settled-turn spacing arm a
    /// rollover. A seat with no policy, or a fraction whose card window is
    /// not yet bound, does not fire.
    pub(super) fn fires(&self) -> bool {
        let Some(threshold) = self.effective_threshold() else {
            return false;
        };
        !self.busy
            && self.measuring.is_none()
            && self.watermark >= threshold
            && self.settled_turns >= crate::live::rollover::ROLLOVER_MIN_SETTLED_TURNS
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.rolls_at_settled_turns())
    }

    /// Records the selected model card's window and the lane ceiling the
    /// trigger resolves against. Identity is not stored: the fraction is a
    /// property of the declaration and the card, not of who selected it.
    pub(super) fn bind_card(&mut self, window: u64, ceiling: u64) {
        self.card_window = window;
        self.card_ceiling = ceiling;
    }
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
