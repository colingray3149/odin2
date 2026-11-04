//! Calls waiting on the owner's yes. A gated call is parked when its approval request is
//! minted; his yes runs it through the same dispatch, once, so the seat's model never
//! has to repeat it.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use odin_domain::{ApprovalId, Scope, SessionId};
use serde_json::Value;
use thiserror::Error;

use super::operations::{
    HostToolOperationError, HostToolOperations, SessionOperationBinding, SessionOperationContext,
};

/// How long an approval request stays decidable, and so how long its call is held.
pub(crate) const REQUEST_LIFE: Duration = Duration::from_secs(3_600);

/// One gated call exactly as its seat made it.
pub(super) struct ParkedCall {
    pub(super) operations: HostToolOperations,
    pub(super) binding: SessionOperationBinding,
    pub(super) session: SessionId,
    pub(super) scope: Scope,
    pub(super) tool: String,
    /// The call's arguments with the minted `approvalId`, as a retry presents them.
    pub(super) arguments: Value,
    pub(super) parked_at: Instant,
}

#[derive(Debug, Error)]
pub enum ApprovedCallError {
    #[error(
        "the call is no longer held (it already ran, or the daemon restarted since it was \
         asked); ask the seat to make it again"
    )]
    NotHeld,
    /// The call was refused when it ran; the text is the refusal's own cause.
    #[error("{}", crate::bridge::model_error_text(&.0.to_string()))]
    Refused(#[from] HostToolOperationError),
}

/// The parked calls of every session, by approval id; the daemon shares one.
#[derive(Default)]
pub struct ApprovedCalls {
    parked: Mutex<BTreeMap<ApprovalId, ParkedCall>>,
}

impl ApprovedCalls {
    pub(super) fn park(&self, approval_id: ApprovalId, call: ParkedCall) {
        if let Ok(mut parked) = self.parked.lock() {
            // A call whose request lapsed can never be approved; stop holding it.
            parked.retain(|_, held| held.parked_at.elapsed() < REQUEST_LIFE);
            parked.insert(approval_id, call);
        }
    }

    /// Runs the call parked for an approved approval. The call leaves the map first, so a
    /// second answer for the same approval finds nothing to run.
    pub fn run(&self, approval_id: &ApprovalId) -> Result<Value, ApprovedCallError> {
        let call = self
            .parked
            .lock()
            .ok()
            .and_then(|mut parked| parked.remove(approval_id))
            .ok_or(ApprovedCallError::NotHeld)?;
        Ok(call.operations.dispatch_tool(
            SessionOperationContext {
                binding: &call.binding,
                session: &call.session,
                scope: &call.scope,
                execution: None,
            },
            &call.tool,
            None,
            call.arguments,
            &format!("approved:{approval_id}"),
        )?)
    }

    /// Forgets a call whose approval was denied, cancelled or expired.
    pub fn release(&self, approval_id: &ApprovalId) {
        if let Ok(mut parked) = self.parked.lock() {
            parked.remove(approval_id);
        }
    }
}
