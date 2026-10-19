//! The public [`OmpBridge`] handle over one supervised pinned-OMP child.

use super::*;

pub struct OmpBridge {
    shared: Arc<Shared>,
}

impl OmpBridge {
    // Failed startup retires the live row so it cannot remain published as ready.
    pub async fn start(config: OmpBridgeConfig) -> Result<Self, BridgeError> {
        config.validate()?;
        let OmpBridgeConfig {
            process,
            worker,
            ledger,
            operations,
            operation_binding,
            admitted_host_tools,
            uri_router,
            artifact_root,
            binding,
            session,
            lease_ttl,
            rollover,
            rollover_children,
            requested_epoch,
            transport,
        } = config;

        // 1. Exclusive durable session lease, before any other effect.
        let lease = acquire_lease_record(&ledger, &binding, lease_ttl).await?;

        // 2. Durable live session. With a requested admission epoch the
        //    binding is forced to EXACTLY that epoch — the supervisor's
        //    durable journal is the epoch authority — so the real launched
        //    binding can never drift from the epoch the client admitted
        //    against. Without one, the legacy reclaim (epoch + 1) stands.
        //    Either way, existing immutable host bindings must match before
        //    an epoch can be published under a reused session id.
        let scope = &binding.scope;
        let session_row = NewLiveSession {
            session_id: binding.session_id.clone(),
            seat_id: scope
                .seat
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            project_id: scope
                .project
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            slice_id: session.slice_id,
            lane_id: binding.lane_id.to_string(),
            target_node_id: session.target_node_id,
            provider: session.provider,
            model: session.model,
            title: session.title,
            manifest: session.manifest,
            open_tab: session.open_tab,
            state: "ready".to_owned(),
            created_at: now_utc(),
        };
        let shared_ledger = Arc::clone(&ledger);
        let session_id = binding.session_id.clone();
        let live_result =
            tokio::task::spawn_blocking(move || -> Result<LiveSession, BridgeError> {
                let mut guard = shared_ledger.lock().map_err(|_| {
                    BridgeError::Ledger(LedgerError::invalid_data(
                        "ledger mutex poisoned".to_owned(),
                    ))
                })?;
                match guard.live_session(&session_id) {
                    Ok(existing) => {
                        validate_existing_live_session(&guard, &session_row)?;
                        match requested_epoch {
                            Some(requested) => {
                                // CHECKED conversion: the requested epoch
                                // must fit the durable epoch range exactly —
                                // no wrapping cast, no defaulted identity.
                                let requested = i64::try_from(requested.get()).map_err(|_| {
                                    BridgeError::Config {
                                        detail: "requested epoch does not fit the durable \
                                                 epoch range"
                                            .to_owned(),
                                    }
                                })?;
                                if existing.epoch > requested {
                                    Err(BridgeError::StaleBinding {
                                        requested,
                                        actual: existing.epoch,
                                    })
                                } else {
                                    Ok(guard.reclaim_live_session_to(
                                        &session_id,
                                        requested,
                                        now_utc(),
                                    )?)
                                }
                            }
                            None => Ok(guard.reclaim_live_session(
                                &session_id,
                                existing.epoch,
                                now_utc(),
                            )?),
                        }
                    }
                    Err(LedgerError::NotFound { .. }) => match requested_epoch {
                        Some(requested) => {
                            let requested = i64::try_from(requested.get()).map_err(|_| {
                                BridgeError::Config {
                                    detail: "requested epoch does not fit the durable epoch \
                                             range"
                                        .to_owned(),
                                }
                            })?;
                            Ok(guard.create_live_session_at(&session_row, requested)?)
                        }
                        None => Ok(guard.create_live_session(&session_row)?),
                    },
                    Err(error) => Err(error.into()),
                }
            })
            .await;
        let live_result = match live_result {
            Ok(result) => result,
            Err(error) => Err(BridgeError::Serialization {
                detail: format!("live-session task failed: {error}"),
            }),
        };
        let live = match live_result {
            Ok(live) => live,
            Err(error) => {
                // No settlement here: this path failed BEFORE owning a row —
                // refused create/reclaim wrote nothing, and a pre-existing row
                // belongs to another incarnation. Only the acquired lease is
                // released.
                if let Err(release_error) = release_lease_record(&ledger, &lease).await {
                    tracing::error!("Releasing the bridge lease after session registration failed: {release_error}");
                }
                return Err(error);
            }
        };

        // Both carriers use the same launcher arguments and RPC handshake.
        let child = match transport.as_ref() {
            Some(factory) => {
                tracing::debug!(session = %binding.session_id, "Skipping model-request ingest for kube-exec carrier: pod transcript reading is unavailable");
                let launch_args: Vec<String> = process.launch_args().collect();
                let channel = factory
                    .attach(&launch_args, &process.explicit_env)
                    .await
                    .map_err(|error| BridgeError::RemoteAttach {
                        detail: error.to_string(),
                    });
                let channel = match channel {
                    Ok(channel) => channel,
                    Err(error) => {
                        return Err(settle_failed_start(&ledger, &lease, &live, error).await);
                    }
                };
                match OmpProcess::spawn_remote(
                    process.clone(),
                    worker.clone(),
                    channel,
                    factory.job_worker_id().clone(),
                    factory.stop_action(),
                )
                .await
                {
                    Ok(child) => child,
                    Err(error) => {
                        return Err(settle_failed_start(&ledger, &lease, &live, error.into()).await);
                    }
                }
            }
            None => {
                if let Err(error) = process.establish_identity(&worker).await {
                    return Err(settle_failed_start(&ledger, &lease, &live, error.into()).await);
                }
                match OmpProcess::spawn(process.clone(), worker.clone()).await {
                    Ok(child) => child,
                    Err(error) => {
                        return Err(settle_failed_start(&ledger, &lease, &live, error.into()).await);
                    }
                }
            }
        };

        // 4. Shared state, sole-owner pump, and lease heartbeat.
        let (pump_tx, pump_rx) = mpsc::channel::<PumpMessage>(64);
        let (observations, internal_rx) =
            broadcast::channel::<ObservedFrame>(OBSERVATION_CHANNEL_CAP);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (failure_notice, _) = watch::channel(None);
        let completed = binding_with(&binding, live.epoch, &lease);
        let id_nonce = binding_nonce(&completed);
        let shared = Arc::new(Shared {
            ledger,
            operations,
            operation_binding,
            admitted_host_tools,
            uri_router,
            dispatch: Arc::new(Semaphore::new(DISPATCH_PERMITS)),
            artifact_root,
            lease_ttl,
            process_spec: process,
            worker,
            transport,
            id_nonce,
            binding: Mutex::new(completed),
            lease: Mutex::new(Some(lease)),
            status: Mutex::new(BridgeStatus::Starting),
            blocked: Mutex::new(Vec::new()),
            correlation: Mutex::new(Correlation::default()),
            side: Mutex::new(SideTable::default()),
            observers: Mutex::new(BTreeMap::new()),
            observations,
            internal_rx: AsyncMutex::new(Some(internal_rx)),
            pump_tx,
            shutdown,
            lifecycle: AsyncMutex::new(()),
            lease_gate: AsyncMutex::new(()),
            child_stop: Mutex::new(None),
            generation: AtomicU64::new(1),
            sequence: AtomicU64::new(0),
            rollover: Mutex::new(RolloverTracker::new(rollover, rollover_children)),
            rollover_wake: Arc::new(Notify::new()),
            listing_bytes: AtomicU64::new(0),
            process_exited: AtomicBool::new(false),
            failure_notice,
        });
        let pump_shared = Arc::clone(&shared);
        drop(tokio::spawn(async move {
            if let Err(error) =
                pump_task(Arc::clone(&pump_shared), pump_rx, shutdown_rx, Some(child)).await
            {
                let _ = pump_shared.mark_failed(&format!("bridge pump task failed: {error}"));
                let _ = pump_shared.shutdown.send(true);
            }
        }));
        drop(tokio::spawn(lease_heartbeat(
            Arc::downgrade(&shared),
            shared.shutdown.subscribe(),
        )));

        let bridge = Self { shared };

        // 5–6. Deterministic registration followed by crash-window
        // reconciliation. A failure explicitly stops/reaps the child and
        // releases the lease before start returns its original error.
        let startup = async {
            bridge.shared.register_host_tools().await?;
            bridge.shared.register_host_uris().await?;
            bridge.shared.reconcile().await
        }
        .await;
        match startup {
            Ok((_reconciled, blocked)) => {
                bridge.shared.set_status(if blocked.is_empty() {
                    BridgeStatus::Ready
                } else {
                    BridgeStatus::Blocked { commands: blocked }
                })?;
                Ok(bridge)
            }
            Err(error) => {
                // A failed first open ends the session's row: the caller
                // derives a fresh session instead of re-driving this one
                // (the launcher maps the ended row to the typed
                // `session_ended` refusal).
                let _ = bridge.stop_ending_session().await;
                Err(error)
            }
        }
    }

    /// The completed binding: scope, ids, owner, epoch, and lease.
    pub fn binding(&self) -> Result<BridgeBinding, BridgeError> {
        self.shared.binding_snapshot()
    }

    /// Subscribes to this bridge's UNEXPECTED-failure notices: `Some`
    /// carries the typed failure reason of the current incarnation, sent
    /// exactly when the pump proves the child can no longer carry traffic.
    /// A planned stop or reclaim never sends here.
    pub fn failed_notices(&self) -> watch::Receiver<Option<String>> {
        self.shared.failure_notice.subscribe()
    }

    /// Installs the bounded parent-stop coordinator exactly once after
    /// start. Runtime composition supplies the hook; the bridge stores it as
    /// a [`std::sync::Weak`] so an owner that strongly owns the supervisor
    /// can never form a reference cycle back into this bridge.
    pub fn set_child_stop_coordinator(
        &self,
        coordinator: &Arc<dyn ChildStopCoordinator>,
    ) -> Result<(), BridgeError> {
        self.shared.set_child_stop_coordinator(coordinator)
    }

    pub fn status(&self) -> Result<BridgeStatus, BridgeError> {
        self.shared.status()
    }
    /// Whether an exit record or completed teardown confirms the child has stopped.
    pub fn process_exited(&self) -> bool {
        self.shared.process_exited()
    }

    /// The provider-reported context watermark of the session's last
    /// settled turn (input + cacheRead + cacheWrite + output), `None`
    /// until a settled turn has reported usage. Measured only — nothing is
    /// ever estimated — and recorded whether or not a rollover policy is
    /// configured, so the live control seam can bound dispatch against the
    /// bound lane's declared window.
    pub fn measured_context_watermark(&self) -> Option<u64> {
        let guard = shared_lock(&self.shared.rollover, "rollover").ok()?;
        guard.last_usage.map(|_| guard.watermark)
    }

    /// The session's context epoch: it changes at every compaction and
    /// rollover, so brain context injected for one epoch is not repeated
    /// on ordinary turns of the same epoch.
    pub fn context_epoch(&self) -> u64 {
        shared_lock(&self.shared.rollover, "rollover").map_or(0, |guard| guard.context_epoch)
    }

    /// Subscribes to every observed frame. Receivers that fall behind the
    /// bounded window receive a typed lag error carrying the missed count.
    /// Durable frames are the ledger journal, not an in-process buffer.
    pub fn subscribe(&self) -> broadcast::Receiver<ObservedFrame> {
        self.shared.observations.subscribe()
    }

    /// Snapshot of the retained side-channel outcomes, plus the count the
    /// bounded history yielded.
    pub fn side_channel_evidence(&self) -> Result<(Vec<SideChannelOutcome>, u64), BridgeError> {
        let guard = self.shared.side_guard()?;
        Ok((guard.history.iter().cloned().collect(), guard.dropped))
    }

    /// Answers a confirmed, outstanding boolean dialog of the current child.
    pub async fn reply_to_confirmation(
        &self,
        request_id: &odin_domain::huginn::PermissionRequestId,
        confirmed: bool,
    ) -> Result<(), BridgeError> {
        self.shared
            .reply_to_confirmation(request_id, confirmed)
            .await
    }

    /// The journaled `prompt` wire frame shared by the awaiting and
    /// open-loop dispatches.
    fn prompt_frame(prompt: Prompt) -> Value {
        let mut frame = json!({
            "type": "prompt",
            "message": prompt.message,
        });
        let object = frame.as_object_mut().expect("frame object literal");
        if !prompt.images.is_empty() {
            let _ = object.insert("images".to_owned(), json!(prompt.images));
        }
        if let Some(behavior) = prompt.streaming_behavior {
            let _ = object.insert("streamingBehavior".to_owned(), json!(behavior.as_str()));
        }
        frame
    }

    /// Journaled pinned `prompt`.
    pub async fn prompt(&self, prompt: Prompt) -> Result<CommandReceipt, BridgeError> {
        self.execute("prompt", Self::prompt_frame(prompt), InFlightKind::Mutating)
            .await
    }

    /// Open-loop `prompt` for the live session control path: the journaled,
    /// write-acknowledged dispatch IS the command's completion. The turn's
    /// outcome arrives as normalized child events (`prompt_result`/`agent_end`
    /// and their terminal frames, plus a typed `Error` event when the
    /// correlated response itself is a rejection), never as this return
    /// value — the live control backend discards the receipt today. Awaiting
    /// the correlated final response inline would park the session actor for
    /// the entire turn and starve every turn-scoped mechanism (the declared
    /// turn budget's give-up, a mid-turn abort) that must act WHILE the turn
    /// is live. The dispatch registers `ReplyDelivery::Observed`: the
    /// correlation entry still tracks the flight to its response (lifecycle
    /// bookkeeping is unchanged), but a typed correlated failure — a
    /// response/command mismatch — is annotated on the observed frame for
    /// the session journal, decided at dispatch time and never by receiver
    /// timing.
    pub async fn prompt_open_loop(&self, prompt: Prompt) -> Result<(), BridgeError> {
        let _dispatched = {
            let _lifecycle = self.shared.lifecycle.lock().await;
            self.shared
                .dispatch(
                    "prompt",
                    Self::prompt_frame(prompt),
                    InFlightKind::Mutating,
                    ReplyDelivery::Observed,
                )
                .await?
        };
        Ok(())
    }

    /// Dispatches a caller-IDed prompt once. Existing unresolved rows return
    /// `false`; only a durable successful response proves prior delivery.
    pub async fn prompt_open_loop_identified(
        &self,
        command_id: &CommandId,
        prompt: Prompt,
    ) -> Result<bool, BridgeError> {
        let _lifecycle = self.shared.lifecycle.lock().await;
        if let Some(delivered) = self.identified_prompt_outcome(command_id).await? {
            return Ok(delivered);
        }
        let _dispatched = self
            .shared
            .dispatch_identified(
                command_id.clone(),
                "prompt",
                Self::prompt_frame(prompt),
                InFlightKind::Mutating,
                ReplyDelivery::Observed,
            )
            .await?;
        Ok(true)
    }

    /// Reads delivery evidence without preparing or resending the prompt.
    /// `None` means absent; `Some(false)` means its effect remains unknown.
    /// Recovery records `CommandFailed` when it confirms no dispatch occurred,
    /// allowing the owner to replace the attempt.
    pub async fn identified_prompt_outcome(
        &self,
        command_id: &CommandId,
    ) -> Result<Option<bool>, BridgeError> {
        let id = command_id.clone();
        let existing = self
            .shared
            .ledger_op(move |ledger| match ledger.live_command(&id) {
                Ok(row) => Ok(Some(row)),
                Err(LedgerError::NotFound { .. }) => Ok(None),
                Err(error) => Err(error),
            })
            .await?;
        if let Some(row) = existing {
            let binding = self.shared.binding_snapshot()?;
            if row.session_id != binding.session_id
                || row.body.get("type").and_then(Value::as_str) != Some("prompt")
            {
                return Err(BridgeError::Config {
                    detail: format!(
                        "prompt command id `{command_id}` belongs to a different request"
                    ),
                });
            }
            let Some(outcome) = row.outcome.filter(|_| row.completed_at.is_some()) else {
                return Ok(Some(false));
            };
            if outcome.get("command").and_then(Value::as_str) != Some("prompt")
                || outcome.get("command_id").and_then(Value::as_str) != Some(command_id.as_str())
            {
                return Ok(Some(false));
            }
            match outcome.get("kind").and_then(Value::as_str) {
                Some("not_dispatched_before_crash") => {
                    return Err(BridgeError::CommandFailed {
                        command: "prompt".to_owned(),
                        error: "the prompt was not dispatched before bridge recovery".to_owned(),
                        code: Some("not_dispatched_before_crash".to_owned()),
                    });
                }
                Some("command_response") => {}
                _ => return Ok(Some(false)),
            }
            return match outcome.get("success").and_then(Value::as_bool) {
                Some(true) => Ok(Some(true)),
                Some(false) => Err(BridgeError::CommandFailed {
                    command: "prompt".to_owned(),
                    error: outcome
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("the model backend rejected the prompt")
                        .to_owned(),
                    code: outcome
                        .get("code")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                }),
                None => Ok(Some(false)),
            };
        }
        Ok(None)
    }

    /// Journaled pinned `steer`.
    pub async fn steer(
        &self,
        message: String,
        images: Vec<Value>,
    ) -> Result<CommandReceipt, BridgeError> {
        let mut frame = json!({ "type": "steer", "message": message });
        if !images.is_empty() {
            let _ = frame
                .as_object_mut()
                .expect("frame object literal")
                .insert("images".to_owned(), json!(images));
        }
        self.execute("steer", frame, InFlightKind::Mutating).await
    }

    /// Journaled pinned `follow_up`.
    pub async fn follow_up(
        &self,
        message: String,
        images: Vec<Value>,
    ) -> Result<CommandReceipt, BridgeError> {
        let mut frame = json!({ "type": "follow_up", "message": message });
        if !images.is_empty() {
            let _ = frame
                .as_object_mut()
                .expect("frame object literal")
                .insert("images".to_owned(), json!(images));
        }
        self.execute("follow_up", frame, InFlightKind::Mutating)
            .await
    }

    /// Journaled pinned `abort`.
    pub async fn abort(&self) -> Result<CommandReceipt, BridgeError> {
        self.execute("abort", json!({ "type": "abort" }), InFlightKind::Mutating)
            .await
    }

    /// Journaled pinned `set_model`.
    pub async fn set_model(
        &self,
        provider: &str,
        model_id: &str,
    ) -> Result<CommandReceipt, BridgeError> {
        let frame = json!({ "type": "set_model", "provider": provider, "modelId": model_id });
        self.execute("set_model", frame, InFlightKind::Mutating)
            .await
    }

    /// Journaled pinned `get_state`; resolves to the child's session state
    /// payload.
    pub async fn state(&self) -> Result<Value, BridgeError> {
        let receipt = self
            .execute(
                "get_state",
                json!({ "type": "get_state" }),
                InFlightKind::Informational,
            )
            .await?;
        Ok(receipt.data)
    }

    async fn state_already_gated(&self) -> Result<Value, BridgeError> {
        let receipt = self
            .execute_already_gated(
                "get_state",
                json!({ "type": "get_state" }),
                InFlightKind::Informational,
            )
            .await?;
        Ok(receipt.data)
    }

    /// Content-addressed checkpoint of the durable session: the pinned
    /// session state plus the session's live-event history become canonical
    /// bytes, written as a content-addressed artifact, registered in the
    /// ledger, created as a checkpoint, and committed — all under the
    /// journaled `checkpoint` command.
    pub async fn checkpoint(&self) -> Result<CheckpointRecord, BridgeError> {
        let _lifecycle = self.shared.lifecycle.lock().await;
        self.shared.ensure_dispatchable("checkpoint")?;
        match self.shared.status()? {
            BridgeStatus::Ready => {}
            BridgeStatus::Blocked { commands } => {
                return Err(BridgeError::BlockedIncomplete { commands })
            }
            BridgeStatus::Starting => {
                return Err(BridgeError::NotReady {
                    state: "starting".to_owned(),
                })
            }
            BridgeStatus::Failed { reason } => {
                return Err(BridgeError::ProcessDown { detail: reason })
            }
            BridgeStatus::Stopped => return Err(BridgeError::Stopped),
        }
        let binding = self.shared.binding_snapshot()?;
        let command_id = self.shared.mint_command_id(&binding);
        let frame = with_request_id(
            json!({ "type": "checkpoint", "hostComposite": true }),
            &command_id.to_string(),
        );
        if let Err(error) = self
            .shared
            .journal_command(&command_id, "checkpoint", &frame)
            .await
        {
            self.shared
                .mark_failed(&format!("checkpoint journal failed: {error}"))?;
            return Err(error);
        }

        let outcome = self.build_checkpoint(&binding).await;
        match outcome {
            Ok(record) => {
                let completion = checkpoint_completion(&record);
                if let Err(failure) = self.shared.complete_command(&command_id, completion).await {
                    self.shared
                        .mark_failed(&format!("checkpoint completion failed: {failure}"))?;
                    return Err(failure);
                }
                Ok(record)
            }
            Err(error) => {
                let completion = json!({
                    "kind": "checkpoint_failed",
                    "error": error.to_string(),
                });
                let _ = self.shared.complete_command(&command_id, completion).await;
                Err(error)
            }
        }
    }

    async fn build_checkpoint(
        &self,
        binding: &BridgeBinding,
    ) -> Result<CheckpointRecord, BridgeError> {
        let state = self.state_already_gated().await?;
        let history = self.history_bodies().await?;
        let bytes = json_bytes(&json!({
            "session_id": binding.session_id.to_string(),
            "epoch": binding.epoch,
            "state": state,
            "events": history,
        }))?;
        let state_digest = Digest::hash(&bytes);
        let hex = digest_hex(&state_digest);
        let relative = format!("{}/{}", &hex[..2], hex);
        let path = self.shared.artifact_root.join(&relative);
        let write_bytes = bytes.clone();
        tokio::task::spawn_blocking(move || write_content_addressed(&path, &write_bytes))
            .await
            .map_err(|error| BridgeError::Serialization {
                detail: format!("artifact writer failed: {error}"),
            })??;

        let checkpoint_id = self.shared.mint_checkpoint_id(binding);
        let run_id = binding.run_id.clone();
        let media_bytes = bytes;
        let (metadata, checkpoint) = self
            .shared
            .ledger_op(move |ledger| {
                let metadata = ledger.register_artifact(ArtifactRegistration {
                    bytes: &media_bytes,
                    media_type: "application/json",
                    storage_path: &relative,
                    retention: RetentionClass::Pinned,
                    created_at: now_utc(),
                })?;
                let checkpoint = ledger.create_checkpoint(&CheckpointSpec {
                    id: checkpoint_id,
                    run_id,
                    command_id: None,
                    compatibility_key: CHECKPOINT_COMPATIBILITY_KEY.to_owned(),
                    artifact_ref: metadata.artifact_id.clone(),
                    artifact_digest: metadata.digest,
                    state_digest,
                    created_at: now_utc(),
                })?;
                let checkpoint =
                    ledger.commit_checkpoint(&checkpoint.id, checkpoint.revision, now_utc())?;
                Ok((metadata, checkpoint))
            })
            .await?;
        if metadata.digest != state_digest {
            return Err(BridgeError::Serialization {
                detail: "artifact digest differs from checkpoint state digest".to_owned(),
            });
        }
        Ok(CheckpointRecord {
            checkpoint,
            artifact: metadata,
            state_digest,
        })
    }

    async fn history_bodies(&self) -> Result<Vec<Value>, BridgeError> {
        let binding = self.shared.binding_snapshot()?;
        let session_id = binding.session_id;
        self.shared
            .ledger_op(move |ledger| {
                Ok(bounded_live_history(ledger, &session_id)?
                    .into_iter()
                    .map(|event| event.body)
                    .collect())
            })
            .await
    }

    /// Restarts and resumes the same session: re-asserts the lease, reclaims
    /// the session (incrementing the ownership epoch), respawns and
    /// identity-checks the pinned child, re-registers the listing-derived
    /// admitted host tools and seven URI schemes, and reconciles journaled
    /// commands from durable history without resending any of them.
    pub async fn recover(&self) -> Result<RecoveryReport, BridgeError> {
        let _lifecycle = self.shared.lifecycle.lock().await;
        let binding = self.shared.binding_snapshot()?;
        if binding.epoch == 0 {
            return Err(BridgeError::NotReady {
                state: "unstarted".to_owned(),
            });
        }
        if matches!(self.shared.status()?, BridgeStatus::Stopped) {
            return Err(BridgeError::Stopped);
        }
        // The recover mechanics are shared with the internal rollover
        // driver: close admission, re-assert the lease, retire the child,
        // reclaim the session epoch (same session id, epoch + 1), respawn
        // with identity check, re-register, and reconcile without resend.
        self.shared
            .recover_sequence(super::recovery::RecoverMode::Normal)
            .await
    }

    /// Starts a fresh conversation at the next epoch with one continuity brief.
    /// Requires rollover configuration and reapplies `selected_model` before reinjection.
    /// Returns the fresh epoch.
    pub async fn rollover_context_refusal(
        &self,
        refusal_event: u64,
        selected_model: Option<(String, String)>,
    ) -> Result<i64, BridgeError> {
        self.shared
            .rollover_context_refusal(refusal_event, selected_model)
            .await
    }

    /// Bounded stop: closes side admission first — no new side-channel task,
    /// task.create included, can start once the stop begins — then awaits
    /// every active delegated child within the stop budget, owns and joins
    /// every admitted effect, proves root and process-group death, and only
    /// then releases the session lease. Any child-await timeout, closed
    /// acknowledgement, process reap failure, side-task failure, or lease
    /// error leaves the bridge blocked and its heartbeat/lease authority
    /// intact for a later retry.
    ///
    /// This ends the RUN, not the session: the durable live row keeps
    /// publishing `ready` — exactly the shape a daemon that died leaves —
    /// so the session stays resumable. The next daemon's reclaim reattaches
    /// it, and the start-time settlement reconciles rows a stopped daemon
    /// left. A stop that must end the session uses
    /// [`Self::stop_ending_session`].
    pub async fn stop(&self) -> Result<StopReport, BridgeError> {
        self.stop_with_session_disposition(false).await
    }

    /// Stops the child and marks the durable session `Ended`, preventing later reclaim.
    /// Failures propagate as with [`Self::stop`].
    pub async fn stop_ending_session(&self) -> Result<StopReport, BridgeError> {
        self.stop_with_session_disposition(true).await
    }

    async fn stop_with_session_disposition(
        &self,
        end_session: bool,
    ) -> Result<StopReport, BridgeError> {
        let _lifecycle = self.shared.lifecycle.lock().await;
        if matches!(self.shared.status()?, BridgeStatus::Stopped) {
            return Err(BridgeError::Stopped);
        }
        let stop_budget = bridge_stop_budget(&self.shared.process_spec);
        // Drain admitted calls before enumerating children so in-flight task_create rows are included.
        self.shared.close_side_admission()?;
        self.shared.drain_side_tasks(stop_budget).await?;
        let children = self.shared.await_delegated_children(stop_budget).await?;
        let (ack_tx, ack_rx) = oneshot::channel();
        let budget = stop_budget;
        let enqueued = tokio::time::timeout(
            budget,
            self.shared.pump_tx.send(PumpMessage::Stop {
                end_session,
                ack: ack_tx,
            }),
        )
        .await
        .map_err(|_| BridgeError::ProcessDown {
            detail: "timed out enqueueing the fail-closed bridge stop".to_owned(),
        })?
        .map_err(|_| BridgeError::ChannelClosed);
        if let Err(error) = enqueued {
            self.shared
                .mark_failed(&format!("bridge stop could not reach the pump: {error}"))?;
            return Err(error);
        }
        let report = match tokio::time::timeout(budget, ack_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(BridgeError::ChannelClosed),
            Err(_) => Err(BridgeError::ProcessDown {
                detail: "timed out before child-tree and side-task cleanup were proven".to_owned(),
            }),
        };
        let mut report = match report {
            Ok(report) => report,
            Err(error) => {
                self.shared
                    .mark_failed(&format!("bridge stop remains fail-closed: {error}"))?;
                return Err(error);
            }
        };
        report.children = children;
        if report
            .exit
            .as_ref()
            .is_some_and(|exit| !exit.termination_proven())
        {
            let error = BridgeError::ProcessDown {
                detail: "pump returned an exit record without an observed root status".to_owned(),
            };
            self.shared.mark_failed(&error.to_string())?;
            return Err(error);
        }

        // Ledger residue is observed while the lease is still held. A ledger
        // error cannot strand a released lease behind an incomplete report.
        report.incomplete = match self.visible_incomplete_commands().await {
            Ok(incomplete) => incomplete,
            Err(error) => {
                self.shared.mark_failed(&format!(
                    "stop residue query failed before lease release: {error}"
                ))?;
                return Err(error);
            }
        };
        report.lease_released = match self.shared.release_lease().await {
            Ok(released) => released,
            Err(error) => {
                self.shared
                    .mark_failed(&format!("stop lease release failed closed: {error}"))?;
                return Err(error);
            }
        };
        let _ = self.shared.shutdown.send(true);
        self.shared.note_process_exited(true);
        self.shared.set_status(BridgeStatus::Stopped)?;
        shared_lock(&self.shared.correlation, "correlation")?.fail_all(BridgeError::ProcessDown {
            detail: "bridge stopped".to_owned(),
        });
        *self.shared.internal_rx.lock().await = None;
        Ok(report)
    }

    /// Conformance-only crash injection. This is crate-private so the frozen
    /// public bridge surface cannot grow a production kill primitive.
    pub(crate) async fn kill_child_for_probe(&self) -> Result<Option<OmpExitRecord>, BridgeError> {
        let _lifecycle = self.shared.lifecycle.lock().await;
        self.shared.close_side_admission()?;
        let (ack_tx, ack_rx) = oneshot::channel();
        self.shared
            .pump_tx
            .send(PumpMessage::Terminate {
                reason: "managed child killed by the M3 conformance probe".to_owned(),
                planned: false,
                ack: ack_tx,
            })
            .await
            .map_err(|_| BridgeError::ChannelClosed)?;
        tokio::time::timeout(bridge_stop_budget(&self.shared.process_spec), ack_rx)
            .await
            .map_err(|_| BridgeError::ProcessDown {
                detail: "timed out waiting for the conformance child kill".to_owned(),
            })?
            .map_err(|_| BridgeError::ChannelClosed)?
    }

    async fn visible_incomplete_commands(&self) -> Result<Vec<CommandId>, BridgeError> {
        let binding = self.shared.binding_snapshot()?;
        let session_id = binding.session_id;
        self.shared
            .ledger_op(move |ledger| {
                Ok(session_commands(ledger, &session_id)?
                    .into_iter()
                    .filter(|command| command.completed_at.is_none())
                    .map(|command| command.command_id)
                    .collect())
            })
            .await
    }

    /// Journaled command execution. The lifecycle gate covers the binding
    /// snapshot, journal append, generation capture, and acknowledged pump
    /// write; it is released before waiting for the correlated response.
    async fn execute(
        &self,
        command: &str,
        frame: Value,
        kind: InFlightKind,
    ) -> Result<CommandReceipt, BridgeError> {
        let dispatched = {
            let _lifecycle = self.shared.lifecycle.lock().await;
            self.shared
                .dispatch(command, frame, kind, ReplyDelivery::Awaited)
                .await?
        };
        Shared::await_dispatched(dispatched).await
    }

    /// Dispatch path for callers already holding the lifecycle gate
    /// (`checkpoint`).
    async fn execute_already_gated(
        &self,
        command: &str,
        frame: Value,
        kind: InFlightKind,
    ) -> Result<CommandReceipt, BridgeError> {
        self.shared
            .execute_already_gated(command, frame, kind)
            .await
    }
}
impl Drop for OmpBridge {
    /// Crash semantics: signals the pump to exit without a durable stop. The
    /// child dies with the pump (kill-on-drop); the lease and any incomplete
    /// commands stay in the ledger for the next owner to reconcile.
    fn drop(&mut self) {
        let _ = self.shared.shutdown.send(true);
    }
}

/// Names the pinned harness's durable transcript of THIS session's latest
/// turn, so a recovery — or a fresh daemon rediscovering the conversation —
/// resumes the same conversation instead of starting a new one. The harness
/// cwd is `<state>/huginn/harness/<session>/<launch>`: the session UUID is
/// taken EXACTLY from this spec's odin-minted harness directory (never from
/// ambient state), while the launch UUID is minted per child start, and the
/// pinned harness stores its transcripts under
/// `<home>/.omp/agent/sessions/<project-slug>/<started-at>_<id>.jsonl`,
/// where each slug carries `<session>-<launch>`. Selection is therefore by
/// the odin-minted session UUID across EVERY launch of the session, and by
/// lexicographically greatest transcript file name (the embedded UTC start
/// stamp) — never a mtime guess and never a file from an unrelated session.
///
/// `Ok(None)` means this session has no transcript yet — legitimate only
/// for a fresh, never-started conversation. An unreadable sessions root, an
/// unreadable project directory, or a selected transcript that cannot be
/// stat'd is `Err`: continuity that exists but cannot be verified is a
/// typed recovery failure, never a silent new empty conversation.
pub fn resumable_transcript(spec: &OmpProcessSpec) -> Result<Option<std::path::PathBuf>, String> {
    let session_dir = spec.cwd.parent().ok_or(
        "harness cwd carries no odin-minted session directory; transcript continuity cannot be verified",
    )?;
    let session_id = session_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .ok_or(
            "harness cwd carries no odin-minted session directory; transcript continuity cannot be verified",
        )?;
    // The needle is the odin-minted session UUID, surrounded by dashes: the
    // pinned harness's project slug always carries it (one project dir per
    // LAUNCH, and a daemon restart mints a fresh launch for the SAME
    // session), so matching every launch of this session in one sweep is
    // exactly the restart-continuity contract.
    let needle = format!("-{session_id}-");
    let home = spec
        .explicit_env
        .iter()
        .find(|(name, _)| name == "HOME")
        .map(|(_, value)| value.clone())
        .ok_or("child environment carries no HOME; transcript continuity cannot be verified")?;
    let sessions = std::path::PathBuf::from(home)
        .join(".omp")
        .join("agent")
        .join("sessions");
    let project_dirs = match std::fs::read_dir(&sessions) {
        Ok(dirs) => dirs,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "transcript sessions root {} is unreadable: {error}",
                sessions.display()
            ))
        }
    };
    let mut best: Option<(String, std::path::PathBuf)> = None;
    for project in project_dirs.flatten() {
        let project_name = project.file_name().to_string_lossy().into_owned();
        if !project_name.contains(&needle) {
            continue;
        }
        let entries = match std::fs::read_dir(project.path()) {
            Ok(entries) => entries,
            Err(error) => {
                return Err(format!(
                    "transcript project dir {} is unreadable: {error}",
                    project.path().display()
                ))
            }
        };
        if !project.path().is_dir() {
            continue;
        }
        for file in entries.flatten() {
            let file_name = file.file_name().to_string_lossy().into_owned();
            if !file_name.ends_with(".jsonl") {
                continue;
            }
            if let Err(error) = file.metadata() {
                return Err(format!(
                    "selected transcript {} is unreadable: {error}",
                    file.path().display()
                ));
            }
            if best
                .as_ref()
                .is_none_or(|(best_name, _)| file_name > *best_name)
            {
                best = Some((file_name, file.path()));
            }
        }
    }
    Ok(best.map(|(_, path)| path))
}

/// Idempotently installs `--resume <value>`: any prior resume pair is
/// replaced, never duplicated, so repeated recoveries of one session keep
/// exactly one resume argument naming the newest transcript.
pub fn set_resume_arg(args: &mut Vec<String>, value: &str) {
    if let Some(pos) = args.iter().position(|argument| argument == "--resume") {
        args.remove(pos);
        if pos < args.len() {
            args.remove(pos);
        }
    }
    args.push("--resume".to_owned());
    args.push(value.to_owned());
}

/// Removes session selectors and transcript imports so respawn starts a fresh,
/// persisted conversation. `--no-session` is removed rather than added because
/// later recovery must select the new transcript instead of the oversized one.
/// Value flags consume a following token only if it is not flag-shaped, matching
/// the pinned parser; `=` forms are removed whole.
pub fn strip_resume_args(args: &mut Vec<String>) {
    let mut index = 0;
    while index < args.len() {
        // All decisions are computed from the borrowed argv first; the
        // mutation below never overlaps a live borrow.
        let (selector, consume_next) = {
            let argument = args[index].as_str();
            let (name, equals_value) = match argument.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (argument, None),
            };
            let takes_value = matches!(name, "--resume" | "--session" | "--fork" | "--session-dir");
            let selector = matches!(
                name,
                "--resume"
                    | "--session"
                    | "--fork"
                    | "--session-dir"
                    | "--continue"
                    | "--from-claude"
                    | "--from-codex"
                    | "--no-session"
            ) || argument == "-r"
                || argument == "-c";
            (selector, selector && equals_value.is_none() && takes_value)
        };
        if selector {
            args.remove(index);
            // Match the pinned parser: only non-flag tokens can be separate values.
            if consume_next && index < args.len() && !args[index].starts_with('-') {
                args.remove(index);
            }
        } else {
            index += 1;
        }
    }
}
