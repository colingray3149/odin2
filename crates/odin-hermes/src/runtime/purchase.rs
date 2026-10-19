//! Purchase execution reuses the dispatch pipeline's command and approval rows;
//! it accepts before exchange and records terminal outcomes in the same ledger.

use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use super::HermesRuntime;

impl HermesRuntime {
    /// Installs an admitted backend once; missing backends refuse purchase submission.
    pub fn bind_purchase_backend(
        &self,
        contract: crate::purchase::PurchaseAdapterContract,
        exchange: Arc<dyn crate::purchase::PurchaseFrameExchange>,
    ) -> Result<(), String> {
        let mut backend = self
            .purchase_backend
            .lock()
            .map_err(|_| "purchase backend state poisoned".to_owned())?;
        if backend.is_some() {
            return Err("a purchase backend is already bound".to_owned());
        }
        *backend = Some((contract, exchange));
        Ok(())
    }

    /// Reads approval identity from the journaled command, never model arguments,
    /// and verifies the consumed command and scope without consuming again.
    pub(super) fn verify_consumed_purchase_approval(
        &self,
        consumed: &odin_omp::host_tools::ConsumedHostCommand,
    ) -> Result<odin_domain::ApprovalId, String> {
        let command_id = consumed.command_id();
        let guard = self
            .purchase_ledger
            .lock()
            .map_err(|_| "the authority ledger lock is poisoned".to_owned())?;
        let command = guard
            .command(command_id)
            .map_err(|error| format!("the journaled host command could not be read: {error}"))?
            .ok_or_else(|| "the consumed host command lives in no durable row".to_owned())?;
        if command.capability_id != *consumed.capability_id()
            || i64::from(consumed.capability_version()) != command.capability_version
            || command.target_kind != consumed.target().kind
            || command.target_id != consumed.target().id
            || command.arguments_hash != consumed.arguments_digest()
        {
            return Err("the journaled host command does not match the consumed proof".to_owned());
        }
        let approval_id = command
            .approval_id
            .clone()
            .ok_or_else(|| "the consumed host command names no approval".to_owned())?;
        let approval = guard
            .approval(&approval_id)
            .map_err(|error| format!("the consumed approval could not be read: {error}"))?
            .ok_or_else(|| {
                format!("the consumed approval {approval_id} lives in no durable row")
            })?;
        if approval.status != odin_domain::ApprovalStatus::Consumed {
            return Err(format!(
                "the operator approval {approval_id} was not consumed by this dispatch"
            ));
        }
        if approval.consumed_by_command_id.as_ref() != Some(command_id) {
            return Err("the consumed approval names a different command".to_owned());
        }
        if approval.scope != consumed.approval_scope() {
            return Err("the consumed approval scope does not match the host permit".to_owned());
        }
        Ok(approval_id)
    }

    /// Accepts the existing journaled intent before exchange, without creating another
    /// command, key or approval; it remains nonterminal until the outcome is known.
    pub(super) fn accept_purchase_intent(
        &self,
        command_id: &odin_domain::CommandId,
        now: OffsetDateTime,
    ) -> Result<(), String> {
        let mut guard = self
            .purchase_ledger
            .lock()
            .map_err(|_| "the authority ledger lock is poisoned".to_owned())?;
        let command = guard
            .command(command_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "the journaled intent row is missing".to_owned())?;
        let recorded = guard
            .record_command(&crate::ingress::respecify_command(&command))
            .map(|claimed| claimed.into_recorded())
            .map_err(|error| error.to_string())?;
        guard
            .accept_command(&recorded, recorded.command().revision, now)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Settles the kernel-journaled intent row terminally: re-present the
    /// identical spec (Existing), accept-if-needed (idempotent for an
    /// already-accepted nonterminal row), then complete. A ledger failure
    /// is RETURNED — the caller witnessed the backend outcome and must
    /// surface uncertainty instead of success; nothing is logged away.
    pub(super) fn record_purchase_terminal(
        &self,
        command_id: &odin_domain::CommandId,
        status: odin_ledger::command::CommandTerminalStatus,
        result: Value,
        now: OffsetDateTime,
    ) -> Result<(), String> {
        let mut guard = self
            .purchase_ledger
            .lock()
            .map_err(|_| "the authority ledger lock is poisoned".to_owned())?;
        let command = guard
            .command(command_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "the journaled intent row is missing".to_owned())?;
        let recorded = guard
            .record_command(&crate::ingress::respecify_command(&command))
            .map(|claimed| claimed.into_recorded())
            .map_err(|error| error.to_string())?;
        let accepted = guard
            .accept_command(&recorded, recorded.command().revision, now)
            .map_err(|error| error.to_string())?;
        guard
            .complete_command(
                &accepted,
                &odin_ledger::command::CommandOutcome { status, result },
                accepted.command().revision,
                now,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}
