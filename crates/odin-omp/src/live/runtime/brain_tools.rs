//! Governed tools reuse the same seat services and canonical URI authority.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use odin_brain::service::BrainService;
use odin_domain::{Scope, SeatId};
use serde_json::{json, Value};

use crate::host_tools::brain::{BrainToolsBackend, TaskNoteInput};
use crate::host_tools::operations::LiveSessionBindings;
use crate::host_tools::HostToolError;
use crate::uri::{ExecutionBinding, ScopedUriRouter};

pub(crate) struct RuntimeBrainTools {
    pub brains: BTreeMap<SeatId, Arc<BrainService>>,
    // The session registry owns operations, which own these tools. Keep
    // this edge weak so stopping the runtime releases the entire graph.
    pub sessions: Weak<LiveSessionBindings>,
    pub router: ScopedUriRouter,
}

impl RuntimeBrainTools {
    fn service(&self, scope: &Scope) -> Result<&Arc<BrainService>, HostToolError> {
        let denied = || HostToolError::Scope {
            tool: "task_note",
            reason: "knowledge requires the registered session's exact seat and lane",
        };
        let seat = scope.seat.as_ref().ok_or_else(denied)?;
        let session = scope.session.as_ref().ok_or_else(denied)?;
        let sessions = self.sessions.upgrade().ok_or_else(|| {
            HostToolError::unavailable("task_note", "knowledge runtime has stopped")
        })?;
        let binding = sessions.binding_for(session).ok_or_else(denied)?;
        if &binding.policy.seat_id != seat || scope.lane.as_ref() != Some(&binding.policy.lane_id) {
            return Err(denied());
        }
        let brain = self.brains.get(seat).ok_or_else(|| {
            HostToolError::unavailable("task_note", "seat has no composed knowledge service")
        })?;
        // The brain is composed once, at odind's startup revision; a
        // session bound to another revision is served only when both
        // publications compose identically (a routine in between).
        if !sessions
            .operations()
            .same_composition(brain.policy().registry_revision, binding.served_revision)
        {
            return Err(HostToolError::unavailable(
                "task_note",
                "knowledge service and session publication revisions differ",
            ));
        }
        Ok(brain)
    }
}

impl BrainToolsBackend for RuntimeBrainTools {
    fn preflight(&self, scope: &Scope) -> Result<(), HostToolError> {
        self.service(scope).map(|_| ())
    }

    fn note(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: TaskNoteInput,
    ) -> Result<Value, HostToolError> {
        self.router
            .prove_brain_execution(scope, execution)
            .map_err(HostToolError::from)?;
        let brain = self.service(scope)?;
        let seat = scope.seat.as_ref().ok_or(HostToolError::Scope {
            tool: "task_note",
            reason: "a bound seat is required",
        })?;
        let now_ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let jobs = self
            .sessions
            .upgrade()
            .and_then(|sessions| {
                sessions
                    .operations()
                    .jobs()
                    .map(|board| board.live_entries(u64::try_from(now_ms).unwrap_or(0)))
            })
            .unwrap_or_default();
        let task = input.task.trim();
        brain
            .pin_task_note(
                seat.as_str(),
                scope.project.as_ref(),
                jobs,
                task,
                &input.note,
            )
            .map_err(|error| HostToolError::unavailable("task_note", error))?;
        Ok(json!({"pinned": true, "task": task}))
    }
}
