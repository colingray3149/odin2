//! Running one admitted host-tool call, whatever carried it: OMP's side
//! channel and loom both dispatch through here. A call of the conversation
//! seat that is still running at its inline deadline detaches into a
//! background job; the model is answered with the job id and the call is
//! watched to the end.

use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_domain::{Scope, SessionId};
use serde_json::{json, Value};

use super::jobs::{JobBoard, DEFAULT_DEADLINE, MIN_DEADLINE};
use super::operations::{
    with_ignored, HostToolOperationError, HostToolOperations, SessionOperationBinding,
    SessionOperationContext,
};
use crate::bridge::{model_error_text, model_tool_text};
use crate::uri::ExecutionBinding;

/// The most a call's own `wait_seconds` may extend its job deadline; the seat
/// tools that accept `wait_seconds` refuse a larger value.
const MAX_WAIT_SECONDS: u64 = 600;

/// A call of the conversation seat that becomes a job if it is still
/// running at its inline deadline. The slot itself is taken only then.
pub(crate) struct ReservedCall {
    pub(crate) jobs: Arc<JobBoard>,
    pub(crate) arguments: Value,
    pub(crate) deadline: Duration,
}

/// The background reservation of one call, when its seat runs it as a job
/// past the inline deadline (never a delegation, whose completion reports itself).
pub(crate) fn reserve_background(
    operations: &HostToolOperations,
    scope: &Scope,
    name: &str,
    arguments: &Value,
) -> Option<ReservedCall> {
    operations
        .jobs()
        .filter(|jobs| {
            jobs.runs_in_background(scope.seat.as_ref(), name)
                && !operations.reports_delegated_completion(name)
        })
        .map(|jobs| ReservedCall {
            deadline: operations
                .declared_timeout(name)
                .unwrap_or(DEFAULT_DEADLINE)
                .max(MIN_DEADLINE)
                + Duration::from_secs(
                    arguments["wait_seconds"]
                        .as_u64()
                        .unwrap_or(0)
                        .min(MAX_WAIT_SECONDS),
                ),
            arguments: arguments.clone(),
            jobs: Arc::clone(jobs),
        })
}

/// One prepared call's dispatch through the sole operation authority, shaped
/// as the model reads it: `{content: [text, images…], details, isError}`.
pub(crate) struct ToolDispatch {
    pub(crate) operations: HostToolOperations,
    pub(crate) binding: SessionOperationBinding,
    pub(crate) session: SessionId,
    pub(crate) scope: Scope,
    pub(crate) execution: ExecutionBinding,
    pub(crate) name: String,
    pub(crate) arguments: Value,
    pub(crate) ignored: Vec<String>,
    pub(crate) request_id: String,
}

impl ToolDispatch {
    pub(crate) fn run(self) -> Result<Value, HostToolOperationError> {
        let result = self.operations.dispatch_tool(
            SessionOperationContext {
                binding: &self.binding,
                session: &self.session,
                scope: &self.scope,
                execution: Some(&self.execution),
            },
            &self.name,
            None,
            self.arguments,
            &self.request_id,
        )?;
        let result = with_ignored(result, &self.ignored);
        let error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (result, images) = split_images(result);
        let text = model_tool_text(&result).map_err(|cause| HostToolOperationError::Arguments {
            detail: format!("the tool result is not serializable: {cause}"),
        })?;
        let mut content = vec![json!({"type": "text", "text": text})];
        content.extend(images);
        Ok(json!({"content": content, "details": result, "isError": error}))
    }
}

/// How an admitted call ended for its caller.
pub(crate) enum Ran<E> {
    /// It answered inline (or its worker failed).
    Done(Result<Result<Value, E>, tokio::task::JoinError>),
    /// It detached into a job; the value is the job's answer to the model.
    Detached(Value),
}

/// Runs `operation` on the blocking pool. A call that may become a job and is
/// still running at the seat's inline deadline detaches; a full board at that
/// moment keeps the call running inline — its answer arrives late, never not at all.
pub(crate) async fn run_detachable<E>(
    name: &str,
    operation: impl FnOnce() -> Result<Value, E> + Send + 'static,
    call: Option<ReservedCall>,
) -> Ran<E>
where
    E: std::fmt::Display + Send + 'static,
{
    // One real start time: the job's run time and its absolute deadline
    // both measure from here, not from when the call detaches.
    let started = Instant::now();
    let progress = odin_domain::progress::Slot::default();
    let slot = progress.clone();
    let mut task =
        tokio::task::spawn_blocking(move || odin_domain::progress::scoped(slot, operation));
    let Some(call) = call else {
        return Ran::Done((&mut task).await);
    };
    let inline = tokio::time::Instant::from_std(started + call.jobs.inline());
    if let Ok(outcome) = tokio::time::timeout_at(inline, &mut task).await {
        return Ran::Done(outcome);
    }
    let Ok(reservation) = call.jobs.try_reserve() else {
        // The board is full at the deadline: the call keeps running inline.
        return Ran::Done((&mut task).await);
    };
    match call.jobs.start(
        reservation,
        name,
        &call.arguments,
        call.deadline,
        started,
        progress,
    ) {
        Ok((id, result)) => {
            tokio::spawn(watch_job(
                Arc::clone(&call.jobs),
                started + call.deadline,
                id,
                task,
            ));
            Ran::Detached(result)
        }
        Err(reason) => {
            // The journal could not record the job. The effect already
            // started, so deliver its eventual result inline.
            tracing::warn!("call remains inline: {reason}");
            Ran::Done((&mut task).await)
        }
    }
}

/// Waits out a job and reports how it ended. Past its deadline it fails by
/// name; the call itself may still finish then, but nothing reports it.
async fn watch_job<E: std::fmt::Display>(
    jobs: Arc<JobBoard>,
    deadline_at: Instant,
    id: String,
    task: tokio::task::JoinHandle<Result<Value, E>>,
) {
    let remaining = deadline_at.saturating_duration_since(Instant::now());
    let outcome = match tokio::time::timeout(remaining, task).await {
        Ok(Ok(Ok(result))) => {
            let text = result["content"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|block| block["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if result["isError"].as_bool() == Some(true) {
                Err(text)
            } else {
                Ok(text)
            }
        }
        Ok(Ok(Err(error))) => Err(model_error_text(&error.to_string())),
        Ok(Err(error)) => Err(format!("the call's worker failed: {error}")),
        Err(_) => Err(
            "it did not finish within its deadline, so it was given up (it may still \
             complete, but nothing will report it)"
                .to_owned(),
        ),
    };
    jobs.finish(&id, outcome);
}

/// Takes a handler's `images` (OMP `ImageContent` blocks) out of its result:
/// they ride the tool result as image blocks, never as text or `details`.
pub(crate) fn split_images(mut result: Value) -> (Value, Vec<Value>) {
    let is_image = |block: &Value| {
        block.get("type").and_then(Value::as_str) == Some("image")
            && block.get("data").is_some_and(Value::is_string)
            && block.get("mimeType").is_some_and(Value::is_string)
    };
    let all_images = result
        .get("images")
        .and_then(Value::as_array)
        .is_some_and(|images| images.iter().all(is_image));
    if !all_images {
        return (result, Vec::new());
    }
    match result
        .as_object_mut()
        .and_then(|object| object.remove("images"))
    {
        Some(Value::Array(images)) => (result, images),
        _ => (result, Vec::new()),
    }
}
