//! Shared bridge state: correlation, side-channel tables, evidence, and the
//! durable bookkeeping behind one supervised pinned-OMP child.

use super::*;

pub(super) struct Shared {
    pub(super) ledger: Arc<Mutex<Ledger>>,
    pub(super) operations: HostToolOperations,
    pub(super) operation_binding: SessionOperationBinding,
    pub(super) admitted_host_tools: BTreeSet<String>,
    pub(super) uri_router: ScopedUriRouter,
    pub(super) dispatch: Arc<Semaphore>,
    pub(super) artifact_root: PathBuf,
    pub(super) lease_ttl: Duration,
    pub(super) process_spec: OmpProcessSpec,
    pub(super) worker: OmpWorkerLaunch,
    /// The host-admitted remote harness factory, when this bridge serves a
    /// workload session over the exec transport. Recovery re-attaches
    /// through it; `None` is the local registered-child carrier.
    pub(super) transport: Option<Arc<dyn RemoteHarnessFactory>>,
    pub(super) id_nonce: String,
    pub(super) binding: Mutex<BridgeBinding>,
    pub(super) lease: Mutex<Option<LeaseRecord>>,
    /// First unexpected failure reason; planned stops do not send notices.
    pub(super) failure_notice: watch::Sender<Option<String>>,
    pub(super) status: Mutex<BridgeStatus>,
    pub(super) blocked: Mutex<Vec<CommandId>>,
    pub(super) correlation: Mutex<Correlation>,
    pub(super) side: Mutex<SideTable>,
    pub(super) observers: Mutex<BTreeMap<u64, Arc<dyn BridgeObserver>>>,
    pub(super) observations: broadcast::Sender<ObservedFrame>,
    pub(super) internal_rx: AsyncMutex<Option<broadcast::Receiver<ObservedFrame>>>,
    pub(super) pump_tx: mpsc::Sender<PumpMessage>,
    pub(super) shutdown: watch::Sender<bool>,
    pub(super) lifecycle: AsyncMutex<()>,
    pub(super) lease_gate: AsyncMutex<()>,
    /// Weakly held bounded parent-stop hook. `Weak` breaks the otherwise
    /// inevitable owner→supervisor→actor→bridge cycle; a dropped coordinator
    /// means the runtime composition is already gone.
    pub(super) child_stop: Mutex<Option<Weak<dyn ChildStopCoordinator>>>,
    pub(super) generation: AtomicU64,
    pub(super) sequence: AtomicU64,
    /// Bounded rollover bookkeeping: policy, measured watermark, settled-turn
    /// counters, and single-flight state. Guarded by its own mutex so the
    /// pump-side note path stays cheap and never blocks the lifecycle lock.
    pub(super) rollover: Mutex<RolloverTracker>,
    /// Wake signal for the reinjection-settle wait; `notify_one` permits are
    /// stored, so a turn noted between a state check and the await still wakes.
    pub(super) rollover_wake: Arc<Notify>,
    /// Serialized bytes of the tool definitions last registered with the
    /// child: the part of every provider request the listing decides.
    pub(super) listing_bytes: AtomicU64,
    /// Set only after a wait/exit record proves the pinned child exited, or
    /// after completed bridge teardown. Stdout EOF, a failed frame, and a
    /// queued stop do not set it. Cleared when recovery installs a new child.
    pub(super) process_exited: AtomicBool,
}

/// Locks a bridge shared-state mutex, reporting a poisoned lock as a typed
/// failure instead of panicking. A poisoned guard means a previous holder
/// panicked mid-update, so the shared state is untrusted and the bridge
/// refuses to continue on guessed state.
pub(super) fn shared_lock<'a, T>(
    mutex: &'a Mutex<T>,
    what: &'static str,
) -> Result<MutexGuard<'a, T>, BridgeError> {
    mutex.lock().map_err(|_| BridgeError::ProcessDown {
        detail: format!("{what} mutex poisoned"),
    })
}

impl Shared {
    pub(super) fn ledger_op<T>(
        &self,
        operation: impl FnOnce(&mut Ledger) -> Result<T, LedgerError> + Send + 'static,
    ) -> impl Future<Output = Result<T, BridgeError>> + Send
    where
        T: Send + 'static,
    {
        let ledger = Arc::clone(&self.ledger);
        async move {
            let outcome = tokio::task::spawn_blocking(move || {
                let mut guard = ledger
                    .lock()
                    .map_err(|_| LedgerError::invalid_data("ledger mutex poisoned".to_owned()))?;
                operation(&mut guard)
            })
            .await
            .map_err(|error| BridgeError::Serialization {
                detail: format!("ledger task failed: {error}"),
            })??;
            Ok(outcome)
        }
    }

    pub(super) fn binding_snapshot(&self) -> Result<BridgeBinding, BridgeError> {
        Ok(shared_lock(&self.binding, "binding")?.clone())
    }

    pub(super) fn update_binding(
        &self,
        apply: impl FnOnce(&mut BridgeBinding),
    ) -> Result<(), BridgeError> {
        let mut guard = shared_lock(&self.binding, "binding")?;
        apply(&mut guard);
        Ok(())
    }

    pub(super) fn lease_snapshot(&self) -> Result<Option<LeaseRecord>, BridgeError> {
        Ok(shared_lock(&self.lease, "lease")?.clone())
    }

    pub(super) fn set_lease(&self, record: Option<LeaseRecord>) -> Result<(), BridgeError> {
        *shared_lock(&self.lease, "lease")? = record;
        Ok(())
    }

    pub(super) fn status(&self) -> Result<BridgeStatus, BridgeError> {
        Ok(shared_lock(&self.status, "status")?.clone())
    }

    pub(super) fn set_status(&self, status: BridgeStatus) -> Result<(), BridgeError> {
        *shared_lock(&self.status, "status")? = status;
        Ok(())
    }
    /// Whether an exit record or teardown confirms the child has stopped.
    pub(super) fn process_exited(&self) -> bool {
        self.process_exited.load(Ordering::Acquire)
    }

    pub(super) fn note_process_exited(&self, exited: bool) {
        self.process_exited.store(exited, Ordering::Release);
    }

    /// Exit records release capacity only after confirmed termination.
    pub(super) fn note_exit_record(&self, exit: Option<&crate::process::OmpExitRecord>) {
        if exit.is_some_and(|record| record.termination_proven()) {
            self.note_process_exited(true);
        }
    }

    pub(super) fn blocked_snapshot(&self) -> Result<Vec<CommandId>, BridgeError> {
        Ok(shared_lock(&self.blocked, "blocked")?.clone())
    }

    pub(super) fn set_blocked(&self, commands: Vec<CommandId>) -> Result<(), BridgeError> {
        *shared_lock(&self.blocked, "blocked")? = commands;
        Ok(())
    }

    pub(super) fn block_command(&self, command_id: CommandId) -> Result<(), BridgeError> {
        let blocked = {
            let mut blocked = shared_lock(&self.blocked, "blocked")?;
            if !blocked.contains(&command_id) {
                blocked.push(command_id);
                blocked.sort();
            }
            blocked.clone()
        };
        if !matches!(self.status()?, BridgeStatus::Stopped) {
            self.set_status(BridgeStatus::Blocked { commands: blocked })?;
        }
        Ok(())
    }

    /// Marks unexpected exits `failed` and session-ending stops `ended`.
    /// Ordinary stops preserve resumability; callers decide whether write errors propagate.
    pub(super) async fn finish_live_row(&self, exit: LiveSessionExit) -> Result<(), BridgeError> {
        let binding = self.binding_snapshot()?;
        finish_live_row_at(&self.ledger, binding.session_id, binding.epoch, exit).await
    }

    pub(super) fn mark_failed(&self, reason: &str) -> Result<(), BridgeError> {
        if matches!(self.status()?, BridgeStatus::Stopped) {
            return Ok(());
        }
        self.set_status(BridgeStatus::Failed {
            reason: reason.to_owned(),
        })?;
        // Notify the supervisor of unexpected failure, never planned retirement.
        let _ = self.failure_notice.send(Some(reason.to_owned()));
        shared_lock(&self.correlation, "correlation")?.fail_all(BridgeError::ProcessDown {
            detail: reason.to_owned(),
        });
        Ok(())
    }

    pub(super) fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn mint_command_id(&self, binding: &BridgeBinding) -> CommandId {
        CommandId::from_parts(
            "odin-omp:cmd",
            unix_ms(now_utc()),
            format!(
                "{}-{}-{}",
                binding.epoch,
                self.next_sequence(),
                self.id_nonce
            ),
        )
        .expect("minted command id satisfies the domain grammar")
    }

    fn mint_event_id(&self, binding: &BridgeBinding) -> EventId {
        EventId::from_parts(
            "odin-omp:ev",
            unix_ms(now_utc()),
            format!(
                "{}-{}-{}",
                binding.epoch,
                self.next_sequence(),
                self.id_nonce
            ),
        )
        .expect("minted event id satisfies the domain grammar")
    }

    pub(super) fn mint_checkpoint_id(&self, binding: &BridgeBinding) -> CheckpointId {
        CheckpointId::from_parts(
            "odin-omp:ckpt",
            unix_ms(now_utc()),
            format!(
                "{}-{}-{}",
                binding.epoch,
                self.next_sequence(),
                self.id_nonce
            ),
        )
        .expect("minted checkpoint id satisfies the domain grammar")
    }

    /// One durable live-event append. Events are appended only after their
    /// referenced data is durable; event bodies are self-contained (blob
    /// references are embedded), so the append itself is the durability
    /// boundary.
    pub(super) async fn append_event(&self, body: Value) -> Result<(), BridgeError> {
        let binding = self.binding_snapshot()?;
        let event = NewLiveEvent {
            event_id: self.mint_event_id(&binding),
            session_id: binding.session_id,
            expected_epoch: binding.epoch,
            occurred_at: now_utc(),
            blob_refs: json!([]),
            body,
        };
        self.ledger_op(move |ledger| ledger.append_live_event_after_blobs(&event))
            .await?;
        Ok(())
    }

    /// Journals one command row plus its issued event before any wire send.
    /// The row precedes the event, so a crash between the two writes leaves a
    /// row that provably never reached the child: the pump only writes frames
    /// after the issued event is durable.
    pub(super) async fn journal_command(
        &self,
        command_id: &CommandId,
        command: &str,
        frame: &Value,
    ) -> Result<(), BridgeError> {
        let binding = self.binding_snapshot()?;
        let session_id = binding.session_id.clone();
        let epoch = binding.epoch;
        let row = NewLiveCommand {
            command_id: command_id.clone(),
            session_id: session_id.clone(),
            expected_epoch: epoch,
            expected_event_head: None,
            body: frame.clone(),
            issued_at: now_utc(),
        };
        let issued = NewLiveEvent {
            event_id: self.mint_event_id(&binding),
            session_id,
            expected_epoch: epoch,
            occurred_at: now_utc(),
            blob_refs: json!([]),
            body: json!({
                "kind": "command_issued",
                "command": command,
                "command_id": command_id.to_string(),
                "frame": frame,
            }),
        };
        self.ledger_op(move |ledger| {
            let head = ledger.reconnect_head(&row.session_id)?;
            let row = NewLiveCommand {
                expected_event_head: Some(head),
                ..row
            };
            match ledger.append_live_command(&row)? {
                odin_ledger::live::AppendLiveCommand::Inserted(_) => {}
                odin_ledger::live::AppendLiveCommand::Existing(_) => {
                    return Err(LedgerError::Conflict(format!(
                        "command id {} already journaled",
                        row.command_id
                    )));
                }
            }
            ledger.append_live_event_after_blobs(&issued)?;
            Ok(())
        })
        .await
    }

    pub(super) async fn complete_command(
        &self,
        command_id: &CommandId,
        outcome: Value,
    ) -> Result<(), BridgeError> {
        let at = now_utc();
        let id = command_id.clone();
        self.ledger_op(move |ledger| {
            match ledger.complete_live_command_once(&id, &outcome, at)? {
                CompleteLiveCommand::Completed(_) | CompleteLiveCommand::Existing(_) => Ok(()),
            }
        })
        .await
    }
}
