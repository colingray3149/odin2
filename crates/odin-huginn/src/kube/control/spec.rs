//! Revision-checked admission and the durable journal spec: the pure
//! per-command Huginn gates, the command-to-reconciler verb table, the
//! canonical ledger `CommandSpec`, and the stable idempotency digest.

use odin_domain::huginn::{HuginnProtocolError, KubeCommand, KubeOperationKind, KubeWorkloadState};
use odin_domain::{CapabilityId, Digest};
use odin_kube::KubeError;
use odin_ledger::command::CommandSpec;
use time::OffsetDateTime;

pub fn epoch_millis(at: OffsetDateTime) -> u64 {
    let seconds = at.unix_timestamp().max(0) as u64;
    seconds
        .saturating_mul(1000)
        .saturating_add(u64::from(at.nanosecond()) / 1_000_000)
}

fn ensure_state(
    actual: KubeWorkloadState,
    allowed: &[KubeWorkloadState],
    operation: &str,
) -> Result<(), HuginnProtocolError> {
    if allowed.contains(&actual) {
        return Ok(());
    }
    Err(HuginnProtocolError::Conflict {
        code: "workloadState".to_string(),
        message: format!("{operation} is not applicable while the workload is {actual:?}"),
    })
}

/// Maps typed reconciler/client failures onto the shared protocol error table.
/// `Unavailable` stays retryable; conflicts and rejections do not.
pub(super) fn protocol_error(error: KubeError) -> HuginnProtocolError {
    match error {
        KubeError::Unavailable { reason } => HuginnProtocolError::Unavailable { code: reason },
        KubeError::Conflict { reason } => HuginnProtocolError::Conflict {
            code: "kubeConflict".to_string(),
            message: reason,
        },
        KubeError::Rejected { reason } => HuginnProtocolError::Conflict {
            code: "kubeRejected".to_string(),
            message: reason,
        },
        KubeError::Storage { reason } => HuginnProtocolError::Unavailable { code: reason },
        KubeError::Api(error) => HuginnProtocolError::Unavailable {
            code: format!("kubeApi: {error}"),
        },
    }
}

/// Verb table: Odin workload command to reconciler operation kind plus the
/// human-readable verb used in journal and event messages.
pub(super) fn operation_for(command: &KubeCommand) -> (KubeOperationKind, &'static str) {
    match command {
        KubeCommand::RetryWorkload { .. } => (KubeOperationKind::Restart, "retry"),
        KubeCommand::SuspendWorkload { .. } => (KubeOperationKind::Pause, "suspend"),
        KubeCommand::ResumeWorkload { .. } => (KubeOperationKind::Resume, "resume"),
        KubeCommand::DeleteWorkload { .. } => (KubeOperationKind::Cancel, "delete"),
        KubeCommand::RehomeWorkload { .. } => (KubeOperationKind::Restart, "rehome"),
    }
}

/// Phone retry permits only terminal or suspended workloads, unlike coordinator restart.
/// Rehome checks target readiness separately and imposes no lifecycle restriction.
pub(super) fn ensure_command_state(
    command: &KubeCommand,
    actual: KubeWorkloadState,
    verb: &str,
) -> Result<(), HuginnProtocolError> {
    let allowed: &[KubeWorkloadState] = match command {
        KubeCommand::RetryWorkload { .. } => &[
            KubeWorkloadState::Failed,
            KubeWorkloadState::Succeeded,
            KubeWorkloadState::Suspended,
        ],
        KubeCommand::SuspendWorkload { .. } => &[
            KubeWorkloadState::Pending,
            KubeWorkloadState::Scheduling,
            KubeWorkloadState::Running,
        ],
        KubeCommand::ResumeWorkload { .. } => &[KubeWorkloadState::Suspended],
        KubeCommand::DeleteWorkload { .. } => &[
            KubeWorkloadState::Pending,
            KubeWorkloadState::Scheduling,
            KubeWorkloadState::Running,
            KubeWorkloadState::Suspended,
        ],
        KubeCommand::RehomeWorkload { .. } => return Ok(()),
    };
    ensure_state(actual, allowed, verb)
}

pub(super) fn event_reason(kind: KubeOperationKind) -> &'static str {
    match kind {
        KubeOperationKind::Create => "odin.kube.create",
        KubeOperationKind::Pause => "odin.kube.suspend",
        KubeOperationKind::Resume => "odin.kube.resume",
        KubeOperationKind::Restart => "odin.kube.retry",
        KubeOperationKind::Cancel => "odin.kube.delete",
        KubeOperationKind::Summarize => "odin.kube.summarize",
    }
}

/// Lowercase label for journal and event messages.
pub(super) fn kind_debug(kind: KubeOperationKind) -> &'static str {
    match kind {
        KubeOperationKind::Create => "create",
        KubeOperationKind::Pause => "pause",
        KubeOperationKind::Resume => "resume",
        KubeOperationKind::Restart => "restart",
        KubeOperationKind::Cancel => "cancel",
        KubeOperationKind::Summarize => "summarize",
    }
}

/// Durable ledger capability bound for each Odin workload verb. Rehome
/// executes as a targeted restart of the run's Job. Shared with the daemon
/// admission port so the approval scope and the journaled command bind to
/// the identical capability identity.
pub fn kube_command_capability(command: &KubeCommand) -> &'static str {
    match command {
        KubeCommand::RetryWorkload { .. } | KubeCommand::RehomeWorkload { .. } => {
            "odin_kube.workload.restart"
        }
        KubeCommand::SuspendWorkload { .. } => "odin_kube.workload.pause",
        KubeCommand::ResumeWorkload { .. } => "odin_kube.workload.resume",
        KubeCommand::DeleteWorkload { .. } => "odin_kube.workload.cancel",
    }
}

/// One canonical durable command spec for a kube command: the exact row the
/// ledger command journal stores and an approval consumption names. Shared
/// by the daemon admission gate — which must journal the command before
/// `approvals.consumed_by_command_id` can reference it — and by
/// [`crate::kube::control::KubeControl::execute`], which idempotently reclaims the identical row.
/// Every binding field is a pure function of the command and approval, so
/// every writer derives the identical row and a divergent spec can never
/// bind the id.
pub fn kube_command_spec(
    command: &KubeCommand,
    approval_id: &odin_domain::ApprovalId,
    at: OffsetDateTime,
) -> Result<CommandSpec, HuginnProtocolError> {
    let arguments =
        serde_json::to_value(command).map_err(|_| HuginnProtocolError::InvalidRequest {
            code: "kubeCommandEncoding".to_string(),
            message: "kube command does not serialize".to_string(),
        })?;
    let arguments_hash = Digest::hash(&serde_json::to_vec(&arguments).map_err(|_| {
        HuginnProtocolError::InvalidRequest {
            code: "kubeCommandEncoding".to_string(),
            message: "kube command does not encode".to_string(),
        }
    })?);
    Ok(CommandSpec {
        id: command.command_id().clone(),
        idempotency_key: command.command_id().to_string(),
        correlation_id: command.run_id().to_string(),
        causation_id: None,
        issuer: "odin.huginn.kube".to_owned(),
        approval_id: Some(approval_id.clone()),
        target_kind: "kubeWorkload".to_owned(),
        target_id: command.run_id().to_string(),
        capability_id: CapabilityId::new(kube_command_capability(command)).map_err(|error| {
            HuginnProtocolError::InvalidRequest {
                code: "kubeCapabilityIdentity".to_string(),
                message: error.to_string(),
            }
        })?,
        capability_version: 1,
        arguments_hash,
        arguments,
        expected_desired_revision: Some(i64::try_from(command.expected_revision()).map_err(
            |_| HuginnProtocolError::InvalidRequest {
                code: "kubeCommandRevision".to_string(),
                message: "expected revision does not fit the durable ledger".to_string(),
            },
        )?),
        issued_at: at,
        expires_at: at + time::Duration::minutes(5),
    })
}

pub(super) fn unavailable_code(code: &str) -> HuginnProtocolError {
    HuginnProtocolError::Unavailable {
        code: code.to_owned(),
    }
}

/// Stable per-verb idempotency digest: the command's declared arguments digest
/// plus the addressed run and kind so distinct operations never collide.
pub(super) fn arguments_digest(command: &KubeCommand) -> Digest {
    let (arguments_digest, run_id) = match command {
        KubeCommand::RetryWorkload {
            arguments_digest,
            run_id,
            ..
        }
        | KubeCommand::SuspendWorkload {
            arguments_digest,
            run_id,
            ..
        }
        | KubeCommand::ResumeWorkload {
            arguments_digest,
            run_id,
            ..
        }
        | KubeCommand::DeleteWorkload {
            arguments_digest,
            run_id,
            ..
        }
        | KubeCommand::RehomeWorkload {
            arguments_digest,
            run_id,
            ..
        } => (*arguments_digest, run_id),
    };
    let kind = match command {
        KubeCommand::RetryWorkload { .. } => "retry",
        KubeCommand::SuspendWorkload { .. } => "suspend",
        KubeCommand::ResumeWorkload { .. } => "resume",
        KubeCommand::DeleteWorkload { .. } => "delete",
        KubeCommand::RehomeWorkload { .. } => "rehome",
    };
    let binding = format!("{}:{}:{}", kind, run_id, arguments_digest);
    Digest::hash(binding.as_bytes())
}
