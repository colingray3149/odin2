//! Side-channel admission, dispatch, and evidence: the bounded active
//! table with its owned task set, the lifecycle-owned dispatch of every
//! admitted call, and the pinned wire result frames.

use super::*;

/// Capacity of the bounded history of terminal side-channel outcomes.
pub const SIDE_CHANNEL_HISTORY_CAP: usize = 256;
/// Total logical request bytes retained by admitted side-channel work.
pub const SIDE_CHANNEL_ACTIVE_BYTE_BUDGET: usize = 16 * 1024 * 1024;
/// Permits bounding every admitted host-tool / URI operation, including its
/// active-table entry, owned task, blocking effect, result send, and outcome
/// journal. Admission acquires a permit before cloning request state.
pub const DISPATCH_PERMITS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SideDisposition {
    Running,
    Cancelled,
}

pub(super) struct SideEntry {
    pub(super) kind: SideChannelKind,
    pub(super) name: String,
    pub(super) retained_bytes: usize,
    pub(super) disposition: SideDisposition,
}

enum SideWork {
    Tool {
        scope: Scope,
        execution: ExecutionBinding,
        arguments: Value,
    },
    Uri {
        scope: Scope,
        execution: ExecutionBinding,
        read: bool,
    },
}

pub(super) struct PreparedSideCall {
    request_id: String,
    kind: SideChannelKind,
    name: String,
    work: SideWork,
    permit: OwnedSemaphorePermit,
}

pub(super) enum SidePreparation {
    Ignored,
    Rejected {
        request_id: String,
        kind: SideChannelKind,
        detail: &'static str,
    },
    Prepared(Box<PreparedSideCall>),
}

pub(super) struct SideTable {
    pub(super) active: HashMap<String, SideEntry>,
    pub(super) active_bytes: usize,
    pub(super) admission_open: bool,
    pub(super) tasks: JoinSet<Result<(), BridgeError>>,
    pub(super) task_failure: Option<String>,
    pub(super) history: VecDeque<SideChannelOutcome>,
    pub(super) confirmations: BTreeMap<String, ConfirmationRequest>,
    pub(super) dropped: u64,
}

impl Default for SideTable {
    fn default() -> Self {
        Self {
            active: HashMap::new(),
            active_bytes: 0,
            admission_open: true,
            tasks: JoinSet::new(),
            task_failure: None,
            history: VecDeque::new(),
            confirmations: BTreeMap::new(),
            dropped: 0,
        }
    }
}

impl SideTable {
    fn reap_finished_tasks(&mut self) {
        while let Some(joined) = self.tasks.try_join_next() {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.admission_open = false;
                    self.task_failure
                        .get_or_insert_with(|| format!("owned side-channel task failed: {error}"));
                }
                Err(error) => {
                    self.admission_open = false;
                    self.task_failure
                        .get_or_insert_with(|| format!("owned side-channel task failed: {error}"));
                }
            }
        }
    }

    pub(super) fn admission_rejection(&self, retained_bytes: usize) -> Option<&'static str> {
        if !self.admission_open {
            Some("side-channel admission is closed")
        } else if self.task_failure.is_some() {
            Some("side-channel task authority is failed")
        } else if self.active.len() >= DISPATCH_PERMITS {
            Some("side-channel active-count ceiling reached")
        } else if self
            .active_bytes
            .checked_add(retained_bytes)
            .is_none_or(|bytes| bytes > SIDE_CHANNEL_ACTIVE_BYTE_BUDGET)
        {
            Some("side-channel active-byte ceiling reached")
        } else {
            None
        }
    }

    pub(super) fn cancel(&mut self, request_id: &str, kind: SideChannelKind) -> bool {
        let Some(entry) = self.active.get_mut(request_id) else {
            return false;
        };
        if entry.kind != kind {
            return false;
        }
        entry.disposition = SideDisposition::Cancelled;
        true
    }

    pub(super) fn remove_active(&mut self, request_id: &str) -> Option<SideEntry> {
        let entry = self.active.remove(request_id)?;
        self.active_bytes = self.active_bytes.saturating_sub(entry.retained_bytes);
        Some(entry)
    }

    /// Retains one terminal outcome; the oldest retained outcome yields to
    /// the bounded history and is counted, never silently dropped.
    pub(super) fn remember(&mut self, outcome: SideChannelOutcome) {
        if self.history.len() >= SIDE_CHANNEL_HISTORY_CAP {
            self.history.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.history.push_back(outcome);
    }
}

impl Shared {
    pub(super) fn side_guard(&self) -> Result<MutexGuard<'_, SideTable>, BridgeError> {
        shared_lock(&self.side, "side-channel")
    }
    /// Reserves every resource synchronously before copying child-controlled
    /// fields. Duplicate ids retain observation evidence but never launch or
    /// answer a second interaction.
    pub(super) fn prepare_side_call(
        &self,
        frame: &DecodedRpcFrame,
        class: FrameClass,
    ) -> Result<SidePreparation, BridgeError> {
        let kind = match class {
            FrameClass::HostTool => SideChannelKind::Tool,
            FrameClass::HostUri => SideChannelKind::Uri,
            _ => return Ok(SidePreparation::Ignored),
        };
        let value = frame.value();
        let Some(request_id) = value.get("id").and_then(Value::as_str) else {
            return Ok(SidePreparation::Ignored);
        };
        let (name, uri_read) = match kind {
            SideChannelKind::Tool => {
                let Some(name) = value.get("toolName").and_then(Value::as_str) else {
                    return Ok(SidePreparation::Ignored);
                };
                (name, false)
            }
            SideChannelKind::Uri => {
                let Some(operation) = value.get("operation").and_then(Value::as_str) else {
                    return Ok(SidePreparation::Ignored);
                };
                let Some(url) = value.get("url").and_then(Value::as_str) else {
                    return Ok(SidePreparation::Ignored);
                };
                (url, operation == "read")
            }
        };
        let retained_bytes = frame.raw().len().max(1);
        let mut table = self.side_guard()?;
        table.reap_finished_tasks();
        if table.active.contains_key(request_id) {
            return Ok(SidePreparation::Ignored);
        }
        let rejection = table.admission_rejection(retained_bytes);
        if let Some(detail) = rejection {
            return Ok(SidePreparation::Rejected {
                request_id: request_id.to_owned(),
                kind,
                detail,
            });
        }
        let permit = match Arc::clone(&self.dispatch).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Ok(SidePreparation::Rejected {
                    request_id: request_id.to_owned(),
                    kind,
                    detail: "side-channel dispatch ceiling reached",
                });
            }
        };

        // All child-controlled allocation happens after the count, byte, and
        // semaphore bounds have admitted this request.
        let request_id = request_id.to_owned();
        let name = name.to_owned();
        // Capture scope and epoch together; later rollover must not refresh this request.
        let binding = self.binding_snapshot()?;
        let scope = binding.dispatch_scope();
        let execution = ExecutionBinding::from_binding(&binding);
        let work = match kind {
            SideChannelKind::Tool => SideWork::Tool {
                scope,
                execution,
                arguments: value.get("arguments").cloned().unwrap_or_else(|| json!({})),
            },
            SideChannelKind::Uri => SideWork::Uri {
                scope,
                execution,
                read: uri_read,
            },
        };
        table.active_bytes += retained_bytes;
        let previous = table.active.insert(
            request_id.clone(),
            SideEntry {
                kind,
                name: name.clone(),
                retained_bytes,
                disposition: SideDisposition::Running,
            },
        );
        debug_assert!(previous.is_none());
        Ok(SidePreparation::Prepared(Box::new(PreparedSideCall {
            request_id,
            kind,
            name,
            work,
            permit,
        })))
    }

    /// Transfers a prepared request into the bridge-owned task set. Closing
    /// admission and cancelling the reservation wins over a delayed start.
    pub(super) fn start_side_call(
        self: &Arc<Self>,
        prepared: Box<PreparedSideCall>,
    ) -> Result<(), (Box<PreparedSideCall>, BridgeError)> {
        let mut table = match self.side_guard() {
            Ok(table) => table,
            Err(error) => return Err((prepared, error)),
        };
        table.reap_finished_tasks();
        let runnable = table.admission_open
            && table.task_failure.is_none()
            && table
                .active
                .get(&prepared.request_id)
                .is_some_and(|entry| entry.disposition == SideDisposition::Running);
        if !runnable {
            return Err((
                prepared,
                BridgeError::SideChannelDrain {
                    detail: "side-channel admission closed before dispatch".to_owned(),
                },
            ));
        }
        let shared = Arc::clone(self);
        table
            .tasks
            .spawn(async move { shared.run_prepared_side_call(*prepared).await });
        Ok(())
    }

    pub(super) fn cancel_side_call(&self, value: &Value) -> Result<(), BridgeError> {
        let target = value
            .get("targetId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let cancel_kind = match value.get("type").and_then(Value::as_str) {
            Some("host_tool_cancel") => SideChannelKind::Tool,
            Some("host_uri_cancel") => SideChannelKind::Uri,
            _ => return Ok(()),
        };
        let _ = self.side_guard()?.cancel(target, cancel_kind);
        Ok(())
    }

    /// Atomically closes admission and suppresses every outstanding result.
    /// Tasks stay owned until `drain_side_tasks` has joined them.
    pub(super) fn close_side_admission(&self) -> Result<(), BridgeError> {
        let mut table = self.side_guard()?;
        table.admission_open = false;
        for entry in table.active.values_mut() {
            entry.disposition = SideDisposition::Cancelled;
        }
        Ok(())
    }

    pub(super) fn open_side_admission(&self) -> Result<(), BridgeError> {
        let mut table = self.side_guard()?;
        table.reap_finished_tasks();
        if let Some(detail) = table.task_failure.clone() {
            return Err(BridgeError::SideChannelDrain { detail });
        }
        if !table.active.is_empty()
            || table.active_bytes != 0
            || !table.tasks.is_empty()
            || self.dispatch.available_permits() != DISPATCH_PERMITS
        {
            return Err(BridgeError::SideChannelDrain {
                detail: format!(
                    "cannot reopen with {} active call(s), {} retained byte(s), {} owned task(s), and {} available permit(s)",
                    table.active.len(),
                    table.active_bytes,
                    table.tasks.len(),
                    self.dispatch.available_permits(),
                ),
            });
        }
        table.admission_open = true;
        Ok(())
    }

    pub(super) async fn abandon_prepared_side_call(
        &self,
        prepared: PreparedSideCall,
        error: &str,
    ) -> Result<(), BridgeError> {
        let entry = { self.side_guard()?.remove_active(&prepared.request_id) };
        let Some(entry) = entry else {
            return Ok(());
        };
        let status = if entry.disposition == SideDisposition::Cancelled {
            SideChannelStatus::Cancelled { result: None }
        } else {
            SideChannelStatus::Failed {
                error: error.to_owned(),
            }
        };
        self.finish_side_outcome(
            &prepared.request_id,
            SideChannelOutcome {
                request_id: prepared.request_id.clone(),
                kind: entry.kind,
                name: entry.name,
                status,
            },
            false,
        )
        .await?;
        Ok(())
    }

    async fn run_prepared_side_call(&self, prepared: PreparedSideCall) -> Result<(), BridgeError> {
        let PreparedSideCall {
            request_id,
            kind,
            name,
            work,
            permit,
        } = prepared;
        match work {
            SideWork::Tool {
                scope,
                execution,
                arguments,
            } => {
                let operations = self.operations.clone();
                let operation_binding = self.operation_binding.clone();
                let session = execution.session_id().clone();
                let dispatch_name = name.clone();
                let request = request_id.clone();
                let operation = move || -> Result<Value, BridgeError> {
                    // Every production tool dispatch enters the sole
                    // operation authority. An unlisted/unbound familiar name
                    // is rejected by HostToolOperations before any handler.
                    let result = operations.dispatch_tool(
                        SessionOperationContext {
                            binding: &operation_binding,
                            session: &session,
                            scope: &scope,
                            execution: Some(&execution),
                        },
                        &dispatch_name,
                        None,
                        arguments,
                        &request,
                    )?;
                    let error = result
                        .get("isError")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let text =
                        model_tool_text(&result).map_err(|cause| BridgeError::Serialization {
                            detail: cause.to_string(),
                        })?;
                    Ok(json!({
                        "content": [{"type": "text", "text": text}],
                        "details": result,
                        "isError": error,
                    }))
                };
                self.run_side_channel(request_id, kind, name, permit, operation)
                    .await?;
            }
            SideWork::Uri {
                scope,
                execution,
                read,
            } => {
                let router = self.uri_router.clone();
                let resolve_url = name.clone();
                let operation = move || -> Result<Value, BridgeError> {
                    if !read {
                        return Err(UriError::WriteRejected { url: resolve_url }.into());
                    }
                    // The router validates execution context for brain reads only.
                    let resolved = router
                        .resolve(&UriContext::with_execution(scope, execution), &resolve_url)
                        .map_err(BridgeError::Uri)?;
                    Ok(uri_result_value(&resolved))
                };
                self.run_side_channel(request_id, kind, name, permit, operation)
                    .await?;
            }
        }
        Ok(())
    }

    /// The owned permit spans the entire task, including blocking effect,
    /// cancellation arbitration, result delivery, and durable outcome.
    async fn run_side_channel(
        &self,
        request_id: String,
        kind: SideChannelKind,
        name: String,
        _permit: OwnedSemaphorePermit,
        operation: impl FnOnce() -> Result<Value, BridgeError> + Send + 'static,
    ) -> Result<(), BridgeError> {
        let outcome = tokio::task::spawn_blocking(operation).await;
        match outcome {
            Ok(Ok(result)) => {
                self.settle_side_call(request_id, kind, name, result)
                    .await?
            }
            Ok(Err(error)) => {
                let detail = error.to_string();
                let result = side_error_result(kind, &model_error_text(&detail));
                self.fail_side_call(request_id, kind, name, detail, result)
                    .await?;
            }
            Err(error) => {
                let detail = format!("side-channel worker failed: {error}");
                let result = side_error_result(kind, &detail);
                self.fail_side_call(request_id, kind, name, detail.clone(), result)
                    .await?;
                self.close_side_admission()?;
                if !matches!(self.status()?, BridgeStatus::Stopped) {
                    self.mark_failed(&detail)?;
                }
            }
        }
        Ok(())
    }

    fn side_disposition(
        &self,
        request_id: &str,
        kind: SideChannelKind,
    ) -> Result<Option<SideDisposition>, BridgeError> {
        Ok(self
            .side_guard()?
            .active
            .get(request_id)
            .filter(|entry| entry.kind == kind)
            .map(|entry| entry.disposition))
    }

    pub(super) fn side_result_authorized(
        &self,
        request_id: &str,
        kind: SideChannelKind,
    ) -> Result<bool, BridgeError> {
        Ok(self.side_disposition(request_id, kind)? == Some(SideDisposition::Running))
    }

    async fn settle_side_call(
        &self,
        request_id: String,
        kind: SideChannelKind,
        name: String,
        result: Value,
    ) -> Result<(), BridgeError> {
        let sent = if self.side_result_authorized(&request_id, kind)? {
            self.send_side_result(&request_id, kind, &result).await
        } else {
            false
        };
        let status = if sent {
            SideChannelStatus::Completed { result, sent: true }
        } else if self.side_disposition(&request_id, kind)? == Some(SideDisposition::Cancelled) {
            SideChannelStatus::Cancelled {
                result: Some(result),
            }
        } else {
            SideChannelStatus::Completed {
                result,
                sent: false,
            }
        };
        self.finish_side_outcome(
            &request_id,
            SideChannelOutcome {
                request_id: request_id.clone(),
                kind,
                name,
                status,
            },
            true,
        )
        .await?;
        Ok(())
    }

    async fn fail_side_call(
        &self,
        request_id: String,
        kind: SideChannelKind,
        name: String,
        detail: String,
        error_result: Value,
    ) -> Result<(), BridgeError> {
        let sent = if self.side_result_authorized(&request_id, kind)? {
            self.send_side_result(&request_id, kind, &error_result)
                .await
        } else {
            false
        };
        let status = if !sent
            && self.side_disposition(&request_id, kind)? == Some(SideDisposition::Cancelled)
        {
            SideChannelStatus::Cancelled {
                result: Some(error_result),
            }
        } else {
            SideChannelStatus::Failed { error: detail }
        };
        self.finish_side_outcome(
            &request_id,
            SideChannelOutcome {
                request_id: request_id.clone(),
                kind,
                name,
                status,
            },
            true,
        )
        .await?;
        Ok(())
    }

    /// Routes side results through a cancellation-aware pump message. A
    /// bounded acknowledgement prevents stop from deadlocking behind a result
    /// that raced admission closure.
    async fn send_side_result(
        &self,
        request_id: &str,
        kind: SideChannelKind,
        result: &Value,
    ) -> bool {
        let generation = self.generation.load(Ordering::Acquire);
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .pump_tx
            .send(PumpMessage::SideResult {
                generation,
                request_id: request_id.to_owned(),
                kind,
                result: result.clone(),
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            return false;
        }
        matches!(
            tokio::time::timeout(self.process_spec.kill_timeout, ack_rx).await,
            Ok(Ok(true))
        )
    }

    /// Journals and retains the terminal outcome before releasing the active
    /// byte reservation. `remove_active` is false only when the reservation
    /// was already removed while abandoning a never-started request.
    async fn finish_side_outcome(
        &self,
        request_id: &str,
        outcome: SideChannelOutcome,
        remove_active: bool,
    ) -> Result<(), BridgeError> {
        self.journal_side_outcome(&outcome).await?;
        let mut table = self.side_guard()?;
        if remove_active {
            let _ = table.remove_active(request_id);
        }
        table.remember(outcome);
        Ok(())
    }

    /// One normalized durable live event per terminal side-channel outcome.
    async fn journal_side_outcome(&self, outcome: &SideChannelOutcome) -> Result<(), BridgeError> {
        let body = json!({
            "kind": "side_channel_outcome",
            "request_id": outcome.request_id,
            "channel": match outcome.kind {
                SideChannelKind::Tool => "tool",
                SideChannelKind::Uri => "uri",
            },
            "name": outcome.name,
            "status": match &outcome.status {
                SideChannelStatus::Completed { result, sent } => json!({
                    "outcome": "completed",
                    "sent": sent,
                    "result": result,
                }),
                SideChannelStatus::Cancelled { result } => json!({
                    "outcome": "cancelled",
                    "result": result,
                }),
                SideChannelStatus::Failed { error } => json!({
                    "outcome": "failed",
                    "error": error,
                }),
            },
        });
        if let Err(error) = self.append_event(body).await {
            self.mark_failed(&format!("side-channel outcome append failed: {error}"))?;
        }
        Ok(())
    }

    /// Joins every admitted wrapper without aborting it. A timeout puts the
    /// still-owning `JoinSet` back into bridge state and fails closed.
    pub(super) async fn drain_side_tasks(&self, budget: Duration) -> Result<(), BridgeError> {
        let (mut tasks, mut failure) = {
            let mut table = self.side_guard()?;
            table.reap_finished_tasks();
            (
                std::mem::replace(&mut table.tasks, JoinSet::new()),
                table.task_failure.clone(),
            )
        };
        let deadline = tokio::time::Instant::now() + budget;
        while !tasks.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, tasks.join_next()).await {
                Ok(Some(Ok(Ok(())))) => {}
                Ok(Some(Ok(Err(error)))) => {
                    failure.get_or_insert_with(|| {
                        format!("owned side-channel task failed while draining: {error}")
                    });
                }
                Ok(Some(Err(error))) => {
                    failure.get_or_insert_with(|| {
                        format!("owned side-channel task failed while draining: {error}")
                    });
                }
                Ok(None) => break,
                Err(_) => {
                    let count = tasks.len();
                    let mut table = self.side_guard()?;
                    debug_assert!(table.tasks.is_empty());
                    table.tasks = tasks;
                    return Err(BridgeError::SideChannelDrain {
                        detail: format!(
                            "timed out with {count} owned task(s), {} active call(s), and {} retained byte(s)",
                            table.active.len(),
                            table.active_bytes,
                        ),
                    });
                }
            }
        }
        let mut table = self.side_guard()?;
        if let Some(detail) = failure {
            table.task_failure = Some(detail.clone());
            table.admission_open = false;
            return Err(BridgeError::SideChannelDrain { detail });
        }
        if !table.active.is_empty()
            || table.active_bytes != 0
            || self.dispatch.available_permits() != DISPATCH_PERMITS
        {
            return Err(BridgeError::SideChannelDrain {
                detail: format!(
                    "joined tasks left {} active call(s), {} retained byte(s), and {} available permit(s)",
                    table.active.len(),
                    table.active_bytes,
                    self.dispatch.available_permits(),
                ),
            });
        }
        Ok(())
    }
}

/// The pinned terminal result frame for one side-channel interaction.
/// Tool results carry an `AgentToolResult`-shaped payload; URI results merge
/// the resolution fields next to `type`/`id` exactly as the pinned schema
/// declares.
pub(super) fn side_result_frame(request_id: &str, kind: SideChannelKind, result: &Value) -> Value {
    match kind {
        SideChannelKind::Tool => json!({
            "type": "host_tool_result",
            "id": request_id,
            "result": result,
            "isError": result.get("isError").and_then(Value::as_bool).unwrap_or(false),
        }),
        SideChannelKind::Uri => {
            let mut wire = json!({
                "type": "host_uri_result",
                "id": request_id,
            });
            if let (Some(object), Some(fields)) = (wire.as_object_mut(), result.as_object()) {
                for (key, value) in fields {
                    if key != "type" && key != "id" {
                        let _ = object.insert(key.clone(), value.clone());
                    }
                }
            }
            wire
        }
    }
}

/// The pinned `isError` result payload answering a failed side-channel call,
/// so the child's pending request always terminates.
pub(super) fn side_error_result(kind: SideChannelKind, detail: &str) -> Value {
    match kind {
        SideChannelKind::Tool => json!({
            "content": [{"type": "text", "text": detail}],
            "isError": true,
        }),
        SideChannelKind::Uri => json!({
            "isError": true,
            "error": detail,
        }),
    }
}

pub(super) fn uri_result_value(resolved: &UriResult) -> Value {
    let mut content_type = match resolved.content_type.as_str() {
        "text/markdown" => "text/markdown",
        "application/json" => "application/json",
        _ => "text/plain",
    };
    let (content, note) = match &resolved.body {
        UriBody::Json(value) => (
            serde_json::to_string(value)
                .expect("serde_json::Value has no non-serializable representation"),
            None,
        ),
        UriBody::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_owned(), None),
            Err(_) => {
                content_type = "application/json";
                (
                    json!({
                        "encoding": "base64",
                        "bytes": base64::engine::general_purpose::STANDARD.encode(bytes),
                    })
                    .to_string(),
                    Some("binary artifact content is represented as canonical base64".to_owned()),
                )
            }
        },
    };
    let mut notes = resolved.notes.clone();
    if let Some(note) = note {
        notes.push(note);
    }
    let mut wire = json!({
        "content": content,
        "contentType": content_type,
        "immutable": resolved.immutable,
    });
    let object = wire.as_object_mut().expect("wire object literal");
    if !notes.is_empty() {
        let _ = object.insert("notes".to_owned(), json!(notes));
    }
    wire
}
