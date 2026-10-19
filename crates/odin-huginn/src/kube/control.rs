//! Revision-checked, idempotent k3s workload controls over Odin-owned runs.
//!
//! This is the real-cluster control surface: every applied command resolves the
//! run's owned Job through the [`JobReconciler`], verifies the run-addressed
//! ownership and `expected_revision` gates against the authoritative cluster
//! observation, and then lets the reconciler perform the actual API-server
//! mutation through the sole `StopAuthority`-registered worker backend.
//! One applied command bumps the workload revision, emits one replace delta,
//! and records one bounded kube event. Commands that resolve to a foreign or
//! absent workload are rejected without any cluster mutation.
//!
//! Admission gating and the durable command spec live in `spec`; outcome
//! projection and the read-model/event feeds live in `projection`.

mod projection;
mod spec;

pub use projection::{publish_deltas, DeltaPublication, KubeEventFrame};
pub use spec::{epoch_millis, kube_command_capability, kube_command_spec};

use odin_domain::huginn::{
    CommandOutcome, CommandReceipt, HuginnProtocolError, KubeCommand, KubeEventType,
    KubeOperationKind, KubeResourceOwnership, Revision,
};
use odin_domain::{ArtifactId, CommandId, RunId};
use odin_kube::{JobAction, JobLaunch, JobObservation, JobReconciler};
use odin_ledger::command::CommandOutcome as LedgerCommandOutcome;
use odin_ledger::command::{CommandTerminalStatus, RecordCommand};
use odin_ledger::Ledger;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tokio::sync::Mutex as AsyncMutex;

use crate::control_core::{failure_from_error, ControlJournal};

use super::view::{kube_object_id, KubeCatalog, KubeEventViewInput};
use projection::ControlState;
use spec::{
    arguments_digest, ensure_command_state, event_reason, kind_debug, operation_for,
    protocol_error, unavailable_code,
};

pub struct KubeControl {
    reconciler: Arc<JobReconciler>,
    /// Placement reader client: the cell's connected clone, used only for
    /// real node inventory refreshes and never for destructive calls.
    placement: odin_kube::KubeClient,
    /// Durable verdict authority: every admission verdict, including
    /// rejections decided before the reconciler is ever called, is recorded
    /// here and replays across restart. The in-memory journal only feeds the
    /// bounded status stream.
    ledger: Arc<Mutex<Ledger>>,
    state: AsyncMutex<ControlState>,
}

impl KubeControl {
    pub fn new(
        catalog: KubeCatalog,
        reconciler: Arc<JobReconciler>,
        ledger: Arc<Mutex<Ledger>>,
        placement: odin_kube::KubeClient,
    ) -> Self {
        Self {
            reconciler,
            placement,
            ledger,
            state: AsyncMutex::new(ControlState {
                catalog,
                journal: ControlJournal::new(),
                deltas: Vec::new(),
                events: Vec::new(),
                event_counter: 0,
            }),
        }
    }

    /// The fixed reconciler API this control drives; shared with the daemon
    /// owner for recovery enumeration and pure reads.
    pub fn reconciler(&self) -> Arc<JobReconciler> {
        Arc::clone(&self.reconciler)
    }

    /// Replays unfinished admitted operations after a (re)connect: journal
    /// entries that began but never settled resume to their durable verdict.
    /// Only journaled operations replay — an operation is here precisely
    /// because its approval was consumed and its metadata claim won — so
    /// recovery never blindly launches unadmitted work. Released Jobs are
    /// not touched: their deletion belongs to the StopAuthority's recovery,
    /// not to operation replay.
    pub async fn recover(&self) -> Result<(), HuginnProtocolError> {
        self.reconciler
            .recover_pending_operations()
            .await
            .map_err(protocol_error)
    }

    /// Real workload creation from a host-built launch. The launch is
    /// assembled only by the trusted host from the admitted published
    /// container profile — image, command, and worker identity never come
    /// from the model. Idempotency is the launch's own operation binding,
    /// enforced by the reconciler; the resulting observation is projected
    /// into the shared read model with one create event.
    pub async fn create(
        &self,
        launch: JobLaunch,
        at: OffsetDateTime,
    ) -> Result<JobObservation, HuginnProtocolError> {
        let operation_tag = launch.operation_id.to_string();
        let observation = self
            .reconciler
            .create(launch)
            .await
            .map_err(protocol_error)?;
        let mut state = self.state.lock().await;
        let mut observation = observation;
        if let Some(delta) = state.ingest(&observation) {
            state.deltas.push(delta);
        }
        // Callers derive their next expected_revision from this view, so it
        // carries the catalog ordinal, never the reconciler's raw view.
        if let Some(projected) = state.catalog.workload(&observation.workload.resource) {
            observation.workload.revision = projected.revision;
        }
        let artifact_id = ArtifactId::from_parts(
            "kube-event",
            epoch_millis(at),
            format!("create-{operation_tag}"),
        )
        .map_err(|error| HuginnProtocolError::InvalidRequest {
            code: "kubeEventIdentity".to_string(),
            message: error.to_string(),
        })?;
        let content = state.catalog.publish_event_message(
            artifact_id,
            event_reason(KubeOperationKind::Create),
            &format!(
                "workload {} created",
                kube_object_id(&observation.workload.resource)
            ),
        )?;
        let revision = state
            .catalog
            .workload(&observation.workload.resource)
            .map(|workload| workload.revision)
            .unwrap_or_default();
        let event = state.catalog.event_view(KubeEventViewInput {
            event_artifact_id: content.artifact_id.clone(),
            resource: observation.workload.resource.clone(),
            revision,
            event_type: KubeEventType::Normal,
            reason: event_reason(KubeOperationKind::Create).to_string(),
            message: format!("workload created for operation {operation_tag}"),
            observed_at: at,
        });
        state.catalog.record_event(event.clone());
        state.events.push(KubeEventFrame { event, content });
        drop(state);
        Ok(observation)
    }

    /// Approved coordinator calls may restart Running workloads, unlike phone commands.
    /// The reconciler checks resourceVersion and routes mutations through StopAuthority.
    pub async fn operate(
        &self,
        action: JobAction,
        at: OffsetDateTime,
    ) -> Result<JobObservation, HuginnProtocolError> {
        self.operate_core(action, at, false).await
    }

    /// [`Self::operate`] for odind-internal commands whose precondition is
    /// their own fresh observation (drain, restore, release, monitor stop):
    /// a version race against the Job controller's status writes re-admits
    /// the same command at the live version (see
    /// `JobReconciler::operate_at_live_version`). Never for a version a
    /// user or model holds — that one stays a typed conflict.
    pub async fn operate_at_live_version(
        &self,
        action: JobAction,
        at: OffsetDateTime,
    ) -> Result<JobObservation, HuginnProtocolError> {
        self.operate_core(action, at, true).await
    }

    async fn operate_core(
        &self,
        action: JobAction,
        at: OffsetDateTime,
        live_version: bool,
    ) -> Result<JobObservation, HuginnProtocolError> {
        let kind = action.kind;
        // Existence and ownership gate against the authoritative view.
        let observation = self
            .reconciler
            .observe_run(&action.run_id)
            .await
            .map_err(protocol_error)?
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "kubeWorkload".to_string(),
                object_id: action.run_id.to_string(),
            })?;
        let owned = matches!(
            &observation.workload.ownership,
            KubeResourceOwnership::Odin { run_id: owned, .. } if owned == &action.run_id
        );
        if !owned {
            return Err(HuginnProtocolError::Conflict {
                code: "foreignResourceImmutable".to_string(),
                message: format!(
                    "k3s object {} is foreign and read-only",
                    kube_object_id(&observation.workload.resource)
                ),
            });
        }

        let updated = if live_version {
            self.reconciler.operate_at_live_version(action).await
        } else {
            self.reconciler.operate(action).await
        }
        .map_err(protocol_error)?;

        let mut state = self.state.lock().await;
        if let Some(delta) = state.ingest(&updated) {
            state.deltas.push(delta);
        }
        let mut observation = updated;
        if let Some(projected) = state.catalog.workload(&observation.workload.resource) {
            observation.workload.revision = projected.revision;
        }
        let artifact_id = ArtifactId::from_parts(
            "kube-event",
            epoch_millis(at),
            format!(
                "operate-{}",
                observation
                    .projection
                    .operation
                    .as_ref()
                    .map(|operation| operation.operation_id.as_str())
                    .unwrap_or("unknown")
            ),
        )
        .map_err(|error| HuginnProtocolError::InvalidRequest {
            code: "kubeEventIdentity".to_string(),
            message: error.to_string(),
        })?;
        let content = state.catalog.publish_event_message(
            artifact_id,
            event_reason(kind),
            &format!(
                "{} applied to {}",
                kind_debug(kind),
                kube_object_id(&observation.workload.resource)
            ),
        )?;
        let revision = state
            .catalog
            .workload(&observation.workload.resource)
            .map(|workload| workload.revision)
            .unwrap_or_else(|| observation.workload.revision);
        let event = state.catalog.event_view(KubeEventViewInput {
            event_artifact_id: content.artifact_id.clone(),
            resource: observation.workload.resource.clone(),
            revision,
            event_type: KubeEventType::Normal,
            reason: event_reason(kind).to_string(),
            message: format!("core {} applied", kind_debug(kind)),
            observed_at: at,
        });
        state.catalog.record_event(event.clone());
        state.events.push(KubeEventFrame { event, content });
        drop(state);
        Ok(observation)
    }

    /// Journals every outcome durably and replays duplicate IDs without rerunning checks.
    /// Pending commands resume admitted operations before fresh checks; statuses remain in memory.
    pub async fn execute(
        &self,
        command: &KubeCommand,
        approval_id: &odin_domain::ApprovalId,
        at: OffsetDateTime,
    ) -> Result<CommandReceipt, HuginnProtocolError> {
        let command_id = command.command_id().clone();

        // In-memory fast path; the durable check below covers restarts.
        {
            let state = self.state.lock().await;
            if let Some(prior_outcome) = state.journal.outcome(&command_id).cloned() {
                return Ok(CommandReceipt::Duplicate {
                    command_id,
                    prior_outcome: Some(Box::new(prior_outcome)),
                });
            }
        }

        let spec = kube_command_spec(command, approval_id, at)?;

        // Reject command-ID reuse with different arguments; replay completed outcomes.
        // Keep the ledger guard within this block so it never crosses an await.
        let verdict = {
            let mut ledger = self
                .ledger
                .lock()
                .map_err(|_| unavailable_code("kubeLedgerLock"))?;
            ledger
                .record_command(&spec)
                .map_err(|_| unavailable_code("kubeCommandJournal"))?
        };
        let (recorded, recover) = match verdict {
            RecordCommand::Existing(stored) => {
                let stored_command = stored.command();
                if stored_command.arguments_hash != spec.arguments_hash
                    || stored_command.target_id != spec.target_id
                    || stored_command.expected_desired_revision != spec.expected_desired_revision
                {
                    let error = HuginnProtocolError::Conflict {
                        code: "commandIdReuse".to_string(),
                        message: "command ID is already bound to different kube arguments"
                            .to_string(),
                    };
                    let mut state = self.state.lock().await;
                    return Err(state.journal.journal_rejected(&command_id, at, error));
                }
                if let Some(result) = &stored_command.terminal_result {
                    if let Ok(prior_outcome) =
                        serde_json::from_value::<CommandOutcome>(result.clone())
                    {
                        return Ok(CommandReceipt::Duplicate {
                            command_id,
                            prior_outcome: Some(Box::new(prior_outcome)),
                        });
                    }
                }
                // Recorded but not terminal: it may own an accepted attempt.
                (stored, true)
            }
            RecordCommand::Inserted(recorded) => (recorded, false),
        };

        // Resume stored admissions before fresh revision, state, and ownership checks.
        let applied = if recover {
            self.recover_admitted(command, &command_id, at).await
        } else {
            self.run(command, &command_id, at).await
        };
        match applied {
            Ok(()) => {
                {
                    let mut ledger = self
                        .ledger
                        .lock()
                        .map_err(|_| unavailable_code("kubeLedgerLock"))?;
                    let accepted = ledger
                        .accept_command(&recorded, recorded.command().revision, at)
                        .map_err(|_| unavailable_code("kubeCommandAccept"))?;
                    let outcome = LedgerCommandOutcome {
                        status: CommandTerminalStatus::Completed,
                        result: serde_json::to_value(&CommandOutcome::Applied {
                            command_id: command_id.clone(),
                        })
                        .map_err(|_| unavailable_code("kubeCommandOutcome"))?,
                    };
                    ledger
                        .complete_command(&accepted, &outcome, accepted.command().revision, at)
                        .map_err(|_| unavailable_code("kubeCommandComplete"))?;
                }
                self.state
                    .lock()
                    .await
                    .journal
                    .journal_completed(&command_id, at);
                Ok(CommandReceipt::Accepted { command_id })
            }
            Err(error) => {
                // Unavailable leaves the reconciler operation pending or
                // uncertain: the verdict stays retryable, so neither the
                // durable record nor the in-memory journal takes a terminal
                // no-effect verdict here and a retry re-runs the recorded,
                // still-non-terminal binding.
                if matches!(error, HuginnProtocolError::Unavailable { .. }) {
                    return Err(error);
                }
                {
                    let mut ledger = self
                        .ledger
                        .lock()
                        .map_err(|_| unavailable_code("kubeLedgerLock"))?;
                    // Durable rejection with the typed failure payload so a
                    // restart replays the identical verdict.
                    let failure = failure_from_error(&error);
                    let outcome = CommandOutcome::Failed {
                        command_id: command_id.clone(),
                        error: failure.clone(),
                    };
                    let result = serde_json::to_value(&outcome)
                        .map_err(|_| unavailable_code("kubeCommandOutcome"))?;
                    ledger
                        .reject_command(&recorded, recorded.command().revision, result, at)
                        .map_err(|_| unavailable_code("kubeCommandReject"))?;
                }
                let mut state = self.state.lock().await;
                Err(state.journal.journal_rejected(&command_id, at, error))
            }
        }
    }

    /// Admission gates against the authoritative cluster observation, then the
    /// reconciler mutation. No gate touches the journal; `execute` records it.
    async fn run(
        &self,
        command: &KubeCommand,
        command_id: &CommandId,
        at: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError> {
        let run_id: &RunId = command.run_id();
        let (kind, verb) = operation_for(command);

        // Authoritative cluster observation for this run. Absent means the
        // run owns no Job: rejected, never fabricated.
        let observation = self
            .reconciler
            .observe_run(run_id)
            .await
            .map_err(protocol_error)?
            .ok_or_else(|| HuginnProtocolError::NotFound {
                object_kind: "kubeWorkload".to_string(),
                object_id: run_id.to_string(),
            })?;

        // Run-addressed ownership gate: the observed Job must belong to this
        // run. Foreign objects stay read-only, however they were observed.
        let owned = matches!(
            &observation.workload.ownership,
            KubeResourceOwnership::Odin { run_id: owned, .. } if owned == run_id
        );
        if !owned {
            return Err(HuginnProtocolError::Conflict {
                code: "foreignResourceImmutable".to_string(),
                message: format!(
                    "k3s object {} is foreign and read-only",
                    kube_object_id(&observation.workload.resource)
                ),
            });
        }

        // Revision gate: the caller addresses the local catalog ordinal it
        // last observed; the exact opaque cluster resourceVersion travels to
        // the reconciler as the real compare-and-swap. First sight of the
        // workload registers it under the next local ordinal first, so a
        // caller whose snapshot predates the daemon's catalog re-observes.
        // The projected advance routes to the drained feed, so an observed
        // cluster update reaches the shared read model even when the gate
        // rejects the command.
        let from_revision = {
            let mut state = self.state.lock().await;
            if let Some(delta) = state.ingest(&observation) {
                state.deltas.push(delta);
            }
            state
                .catalog
                .workload(&observation.workload.resource)
                .map(|workload| workload.revision)
                .ok_or_else(|| HuginnProtocolError::Conflict {
                    code: "foreignResourceImmutable".to_string(),
                    message: format!(
                        "k3s object {} is foreign and read-only",
                        kube_object_id(&observation.workload.resource)
                    ),
                })?
        };
        if command.expected_revision() != from_revision {
            return Err(HuginnProtocolError::RevisionMismatch {
                expected: Revision::new(command.expected_revision()),
                actual: Revision::new(from_revision),
            });
        }

        // Exact per-command observed-state gate (rehome gates only on the
        // target node below).
        ensure_command_state(command, observation.workload.state, verb)?;

        // Rehome requires an observed, ready target node before mutating.
        // If the target is not yet projected, the real inventory is
        // listed once through the placement reader; a node still absent
        // afterwards is a genuine NotFound and readiness is never fabricated.
        if let KubeCommand::RehomeWorkload { target_node, .. } = command {
            let observed = {
                let state = self.state.lock().await;
                state
                    .catalog
                    .node(target_node.as_str())
                    .map(|node| node.state)
            };
            let observed = match observed {
                Some(node_state) => Some(node_state),
                None => {
                    // The inventory's first item is one authoritative node
                    // list; the stream is dropped before any watch opens.
                    let mut inventory = odin_kube::watch::node_inventory(self.placement.clone())
                        .await
                        .map_err(protocol_error)?;
                    if let Some(listed) = futures_util::StreamExt::next(&mut inventory).await {
                        self.observe_nodes(listed.map_err(protocol_error)?)
                            .await
                            .map_err(protocol_error)?;
                    }
                    let state = self.state.lock().await;
                    state
                        .catalog
                        .node(target_node.as_str())
                        .map(|node| node.state)
                }
            };
            match observed {
                None => {
                    return Err(HuginnProtocolError::NotFound {
                        object_kind: "kubeNode".to_string(),
                        object_id: target_node.to_string(),
                    });
                }
                Some(odin_domain::huginn::KubeNodeState::Ready) => {}
                Some(_) => {
                    return Err(HuginnProtocolError::Conflict {
                        code: "nodeNotReady".to_string(),
                        message: format!("rehome target node {target_node} is not ready"),
                    });
                }
            }
        }

        let action = JobAction {
            run_id: run_id.clone(),
            kind,
            expected_resource_version: observation.projection.identity.resource_version.clone(),
            operation_id: odin_types::OperationId::new(&command_id.to_string()).map_err(
                |error| HuginnProtocolError::InvalidRequest {
                    code: "kubeOperationIdentity".to_string(),
                    message: error.to_string(),
                },
            )?,
            idempotency_digest: arguments_digest(command),
            target_node: match command {
                KubeCommand::RehomeWorkload { target_node, .. } => Some(target_node.to_string()),
                _ => None,
            },
        };
        let updated = self
            .reconciler
            .operate(action)
            .await
            .map_err(protocol_error)?;

        self.publish_applied(command, &updated, command_id, at, true)
            .await
    }

    /// Resumes the stored admission, or runs fresh checks if no admission exists.
    /// Unavailable results leave the command pending for another attempt.
    async fn recover_admitted(
        &self,
        command: &KubeCommand,
        command_id: &CommandId,
        at: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError> {
        let (kind, _) = operation_for(command);
        let operation_id =
            odin_types::OperationId::new(&command_id.to_string()).map_err(|error| {
                HuginnProtocolError::InvalidRequest {
                    code: "kubeOperationIdentity".to_string(),
                    message: error.to_string(),
                }
            })?;
        match self
            .reconciler
            .recover_admitted_operation(
                &operation_id,
                command.run_id(),
                kind,
                &arguments_digest(command),
            )
            .await
        {
            Ok(Some(observation)) => {
                self.publish_applied(command, &observation, command_id, at, false)
                    .await
            }
            Ok(None) => self.run(command, command_id, at).await,
            Err(error) => Err(protocol_error(error)),
        }
    }
}
