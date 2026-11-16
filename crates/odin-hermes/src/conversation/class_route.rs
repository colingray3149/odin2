//! Declared class routing, applied only between turns. Evidence is consumed by the same
//! journaled SetModel control as the move; it is never a scorer or a second routing service.
//! Routing retains the cached model-book snapshot by shared ownership, without copying it.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::huginn::{
    ClassRouteDecision, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery, LiveCommand,
    LiveCommandBody, LiveEvent, LiveEventBody, LiveSessionState, LiveSessionSummary, ModelName,
    ProviderName, ToolResultBlock,
};
use odin_kernel::provider::class::Needs;
use odin_omp::host_tools::delegation::{provider_fault_kind, ProviderFaultKind};
use serde_json::Value;

use super::history::PROVIDER_TURN_ERROR;
use super::identity::bounded_command;
use super::ConversationRoot;
use crate::runtime::images::carries_image;
use crate::runtime::models::{note_refusal, read_book, Reading};

#[derive(Default)]
struct RouteHistory {
    class: Option<String>,
    model: Option<String>,
    consumed_owner: Option<String>,
    warrant: Option<String>,
    consumed_reviews: BTreeSet<String>,
    tools: BTreeMap<String, String>,
    failures: BTreeMap<(String, String), BTreeSet<String>>,
    /// The last turn's provider error (message, HTTP status), until a later answer or decision.
    provider_error: Option<(String, Option<u16>)>,
}

impl RouteHistory {
    fn observe(&mut self, event: &LiveEvent) {
        match &event.body {
            LiveEventBody::ModelRouted(route) => {
                if let Some(warrant) = &route.decision.warrant {
                    if warrant.starts_with("reviewer change request:") {
                        self.consumed_reviews.insert(warrant.clone());
                    }
                }
                if route.applied {
                    self.class = Some(route.decision.to_class.clone());
                    self.model = Some(route.model.clone());
                }
                self.consumed_owner = route.decision.owner_message.clone();
                // A decision consumes the entire preceding batch, even on refusal. In
                // particular two failures must not buy both fast→standard and standard→strong.
                self.warrant = None;
                self.tools.clear();
                self.failures.clear();
                self.provider_error = None;
            }
            LiveEventBody::UserMessage(_) => {
                self.tools.clear();
                self.failures.clear();
                self.warrant = None;
                self.provider_error = None;
            }
            LiveEventBody::AssistantMessage(_) => self.provider_error = None,
            LiveEventBody::Error(error) if error.code == PROVIDER_TURN_ERROR => {
                self.provider_error = Some((error.message.clone(), error.error_status));
            }
            LiveEventBody::ToolStarted(start) => {
                self.tools.insert(
                    start.tool.tool_use_id.clone(),
                    start.tool.capability_id.to_string(),
                );
            }
            LiveEventBody::ToolFinished(finished) => {
                let result = &finished.result;
                let Some(tool) = self.tools.get(&result.tool_use_id) else {
                    return;
                };
                let Some(value) = structured_result(result) else {
                    return;
                };
                if result.is_error {
                    if let Some(kind) = value
                        .pointer("/details/errorKind")
                        .or_else(|| value.get("errorKind"))
                        .and_then(Value::as_str)
                        .filter(|kind| matches!(*kind, "arguments" | "adapter_failed"))
                    {
                        let calls = self
                            .failures
                            .entry((tool.clone(), kind.to_owned()))
                            .or_default();
                        calls.insert(result.tool_use_id.clone());
                        if calls.len() >= 2 {
                            self.warrant =
                                Some(format!("repeated typed tool failure: {tool} ({kind})"));
                        }
                    }
                } else if matches!(
                    tool.as_str(),
                    "test.run" | "test_run" | "code.diagnostics" | "code_diagnostics"
                ) && value.get("ok").and_then(Value::as_bool) == Some(false)
                {
                    self.warrant = Some(format!("failing check: {tool}"));
                } else if value.pointer("/verdict/approve").and_then(Value::as_bool) == Some(false)
                {
                    let warrant = format!(
                        "reviewer change request: {tool} ({})",
                        value
                            .get("diffDigest")
                            .and_then(Value::as_str)
                            .unwrap_or(&result.tool_use_id)
                    );
                    if !self.consumed_reviews.contains(&warrant) {
                        self.warrant = Some(warrant);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The provider fault that refuses a lane's account for a while (a usage limit or a rejected
/// key), not a context refusal of one request, which another lane would not change either.
fn refusing_fault(message: &str, status: Option<u16>) -> Option<ProviderFaultKind> {
    provider_fault_kind(message, status).filter(|kind| {
        kind.refuses_lane()
            && !matches!(
                kind,
                ProviderFaultKind::ContextOverflow | ProviderFaultKind::ContextGuard
            )
    })
}

/// Decode only a structured tool result, never error words in assistant/tool prose.
fn structured_result(result: &ToolResultBlock) -> Option<Cow<'_, Value>> {
    let mut value = result.details.as_ref()?;
    // The side-channel keeps the original output under details; failed dispatches
    // keep their canonical errorKind there instead.
    while let Some(details) = value.get("details").filter(|details| details.is_object()) {
        value = details;
    }
    if value.get("errorKind").is_some()
        || value.get("ok").is_some()
        || value.get("verdict").is_some()
    {
        return Some(Cow::Borrowed(value));
    }
    value.get("content")?.as_array()?.iter().find_map(|block| {
        serde_json::from_str(block.get("text")?.as_str()?)
            .ok()
            .map(Cow::Owned)
    })
}

fn next_class(class: &str) -> Result<&'static str, String> {
    match class {
        "fast" => Ok("standard"),
        "standard" => Ok("strong"),
        "strong" => Err("strong is the declared class ceiling".to_owned()),
        _ => Err(format!("class {class} is not fast, standard or strong")),
    }
}

/// The owner asking for more effort: a leading redo, or "think hard" anywhere in his words.
fn owner_warrant(content: &str) -> Option<&'static str> {
    if owner_redo(content) {
        Some("owner redo")
    } else if content.to_ascii_lowercase().contains("think hard") {
        Some("owner asked to think hard")
    } else {
        None
    }
}

/// The owner's explicit redo instruction, not a mention inside quoted/context prose.
fn owner_redo(content: &str) -> bool {
    let content = content.trim_start();
    content
        .get(..4)
        .is_some_and(|word| word.eq_ignore_ascii_case("redo"))
        && content.get(4..).is_some_and(|rest| {
            rest.is_empty()
                || rest
                    .starts_with(|c: char| c.is_whitespace() || matches!(c, ':' | ',' | '.' | '!'))
        })
}

impl ConversationRoot {
    async fn route_history(&self, summary: &LiveSessionSummary) -> Result<RouteHistory, String> {
        let mut history = RouteHistory::default();
        let mut after = EventSeq::new(0);
        while after < summary.event_head {
            let page = self
                .plane
                .history(HistoryQuery {
                    session_id: summary.session_id,
                    after,
                    limit: super::history::page_limit(),
                })
                .await
                .map_err(|error| format!("class route history is unreadable: {error}"))?;
            let previous = after;
            for event in page.events {
                if event.sequence > summary.event_head {
                    break;
                }
                after = event.sequence;
                history.observe(&event);
            }
            if after <= previous {
                return Err("class route history stopped before the turn boundary".to_owned());
            }
        }
        Ok(history)
    }

    pub(super) async fn route_turn(
        &self,
        summary: &LiveSessionSummary,
        content: &str,
        owner_message: Option<&str>,
    ) -> Option<LiveSessionSummary> {
        let route = self.class_route.clone()?;
        if summary.state != LiveSessionState::Idle {
            return None;
        }
        let reading = match tokio::task::spawn_blocking(move || read_book(&route.gateway)).await {
            Ok(Ok(reading)) => Ok(reading),
            Ok(Err(error)) => Err(format!("the model book is unreadable: {error}")),
            Err(error) => Err(format!("the model book read stopped: {error}")),
        };
        self.route_with_reading(summary, content, owner_message, reading)
            .await
    }

    pub(super) async fn route_with_reading(
        &self,
        summary: &LiveSessionSummary,
        content: &str,
        owner_message: Option<&str>,
        reading: Result<Arc<Reading>, String>,
    ) -> Option<LiveSessionSummary> {
        let route = self.class_route.as_ref()?;
        if summary.state != LiveSessionState::Idle {
            return None;
        }
        let history = match self.route_history(summary).await {
            Ok(history) => history,
            Err(error) => {
                tracing::warn!("{error}; class routing refused before the turn");
                return None;
            }
        };
        let class = history.class.as_deref().unwrap_or(route.class);
        // A refused lane is held at once, so this turn's pick passes it over.
        let refused = history
            .provider_error
            .as_ref()
            .and_then(|(message, status)| refusing_fault(message, *status));
        if let (Some(kind), Ok(reading)) = (refused, &reading) {
            note_refusal(&reading.book, summary.model.as_str(), kind.plain());
        }
        let owner = owner_message
            .filter(|key| history.consumed_owner.as_deref() != Some(*key))
            .and_then(|_| owner_warrant(content));
        let warrant = owner.map(str::to_owned).or(history.warrant);
        let manual = history
            .model
            .as_deref()
            .map_or(summary.model != self.model, |model| {
                model != summary.model.as_str()
            });
        // An owner-chosen lane is not moved; its refusal is on the board and reaches the owner.
        if refused.is_some() && manual {
            return None;
        }
        let target = if warrant.is_some() && !manual {
            next_class(class)
        } else {
            Ok(class)
        };
        let needs = Needs {
            vision: carries_image(content),
            ..Needs::default()
        };
        let fallback = reading.as_ref().ok().and_then(|reading| {
            reading
                .validate_launches(
                    self.binding
                        .launch_options
                        .iter()
                        .map(|option| option.model.as_str()),
                )
                .ok()?;
            reading
                .next_lane(
                    class,
                    summary.model.as_str(),
                    !manual && history.model.is_some(),
                    needs,
                )
                .ok()
                .flatten()
        });
        let selection = match (target, &reading) {
            (Err(reason), _) => Err(reason),
            (_, Err(reason)) => Err(reason.clone()),
            (Ok(target), Ok(reading)) => {
                let declared = reading.validate_launches(
                    self.binding
                        .launch_options
                        .iter()
                        .map(|option| option.model.as_str()),
                );
                match declared {
                    Err(reason) => Err(reason),
                    Ok(()) if warrant.is_some() && manual => {
                        Err("the owner's manual model choice is still selected".to_owned())
                    }
                    Ok(()) if warrant.is_some() => match route.escalation.as_deref() {
                        Some(lane) if reading.admits(lane, needs) => {
                            Ok((target.to_owned(), Some(lane.to_owned())))
                        }
                        _ => reading
                            .pick(target, needs)
                            .map(|lane| (target.to_owned(), Some(lane))),
                    },
                    Ok(()) => {
                        let routed = !manual
                            && (history.model.as_deref() == Some(summary.model.as_str())
                                || self.routed.lock().as_ref() == Some(&summary.model));
                        reading
                            .next_lane(target, summary.model.as_str(), routed, needs)
                            .map(|lane| (target.to_owned(), lane))
                    }
                }
            }
        };
        let (target, lane, refusal) = match selection {
            Ok((_, None)) => return None,
            Ok((target, Some(lane))) => (target, lane, None),
            Err(reason) => {
                tracing::warn!(
                    "class {class}: {reason}; the turn stays on {}",
                    summary.model
                );
                // No warrant, no move and no new decision to journal.
                warrant.as_ref()?;
                (class.to_owned(), summary.model.to_string(), Some(reason))
            }
        };
        let option = self
            .binding
            .launch_options
            .iter()
            .find(|option| option.model.as_str() == lane);
        let (provider, model, refusal) = match option {
            Some(option) => (option.provider.clone(), option.model.clone(), refusal),
            None => (
                summary.provider.clone(),
                summary.model.clone(),
                Some(format!(
                    "class {target} picked {lane}, which seat {} does not declare as a launch",
                    self.binding.seat_id
                )),
            ),
        };
        let decision = ClassRouteDecision {
            from_class: class.to_owned(),
            to_class: target,
            warrant,
            through: summary.event_head,
            owner_message: owner_message.map(str::to_owned),
            refusal,
        };
        let moved = decision.refusal.is_none();
        if let Err(error) = self
            .set_model(summary, provider, model.clone(), decision)
            .await
        {
            tracing::warn!(
                "class {class}: SetModel refused: {error}; the turn stays on {}",
                summary.model
            );
            return None;
        }
        if moved {
            *self.routed.lock() = Some(model);
        }
        let mut summary = match self.find_session(summary.session_id, false).await {
            Ok(Some(summary)) => summary,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!("class route: session after SetModel is unreadable: {error}");
                return None;
            }
        };
        // A refused escalation must not suppress the existing photo/window route.
        if !moved {
            if let Some(option) = fallback.as_ref().and_then(|lane| {
                self.binding
                    .launch_options
                    .iter()
                    .find(|option| option.model.as_str() == lane)
            }) {
                let decision = ClassRouteDecision {
                    from_class: class.to_owned(),
                    to_class: class.to_owned(),
                    warrant: None,
                    through: summary.event_head,
                    owner_message: owner_message.map(str::to_owned),
                    refusal: None,
                };
                if self
                    .set_model(
                        &summary,
                        option.provider.clone(),
                        option.model.clone(),
                        decision,
                    )
                    .await
                    .is_ok()
                {
                    *self.routed.lock() = Some(option.model.clone());
                    if let Ok(Some(moved)) = self.find_session(summary.session_id, false).await {
                        summary = moved;
                    }
                }
            }
        }
        Some(summary)
    }

    async fn set_model(
        &self,
        summary: &LiveSessionSummary,
        provider: ProviderName,
        model: ModelName,
        route: ClassRouteDecision,
    ) -> Result<(), String> {
        let command_id = bounded_command(
            "class-route",
            &[
                &summary.session_id.to_string(),
                &summary.event_head.get().to_string(),
                route.owner_message.as_deref().unwrap_or(""),
                model.as_str(),
            ],
        )?;
        let command = LiveCommand {
            command_id,
            session_id: summary.session_id,
            expected_epoch: summary.epoch,
            expected_event_head: Some(summary.event_head),
            body: LiveCommandBody::SetModel {
                provider,
                model,
                route: Some(route),
            },
        };
        self.apply_control(summary, command).await
    }

    /// Sends one control and reads its journaled completion, which is the actor's word that it
    /// took effect: the next command cannot race it.
    pub(super) async fn apply_control(
        &self,
        summary: &LiveSessionSummary,
        command: LiveCommand,
    ) -> Result<(), String> {
        let receipt = self
            .plane
            .command(command.clone())
            .await
            .map_err(|error| error.to_string())?;
        if let CommandReceipt::Rejected { reason, .. } = receipt {
            return Err(format!("{reason:?}"));
        }
        let mut after = summary.event_head;
        loop {
            let page = self
                .plane
                .history(HistoryQuery {
                    session_id: summary.session_id,
                    after,
                    limit: super::history::page_limit(),
                })
                .await
                .map_err(|error| error.to_string())?;
            if page.events.is_empty() {
                return Err(format!(
                    "{:?} has no journaled completion",
                    command.body.kind()
                ));
            }
            for event in page.events {
                after = event.sequence;
                match event.body {
                    LiveEventBody::ControlCompleted(CommandOutcome::Applied { command_id })
                        if command_id == command.command_id =>
                    {
                        return Ok(())
                    }
                    LiveEventBody::ControlCompleted(CommandOutcome::Failed {
                        command_id,
                        error,
                    }) if command_id == command.command_id => return Err(error.message),
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::{
        LiveContentBlock, LiveSessionId, ModelRouted, SessionEpoch, ToolFinished, ToolStarted,
        ToolUseBlock,
    };
    use odin_domain::{CapabilityId, CommandId, EventId, TurnId};
    use serde_json::json;
    use time::OffsetDateTime;

    #[test]
    fn prepayment_refusal_holds_account_without_holding_outages_or_context_errors() {
        assert_eq!(
            refusing_fault("litellm.APIError: prepayment credits depleted", Some(402)),
            Some(ProviderFaultKind::UsageLimit)
        );
        assert_eq!(refusing_fault("gateway unavailable", Some(503)), None);
        assert_eq!(refusing_fault("maximum context length", Some(400)), None);
    }

    fn event(body: LiveEventBody) -> LiveEvent {
        LiveEvent::new(
            1,
            EventId::new("event:test").unwrap(),
            LiveSessionId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            SessionEpoch::new(1),
            EventSeq::new(1),
            OffsetDateTime::UNIX_EPOCH,
            body,
        )
        .unwrap()
    }

    fn result(history: &mut RouteHistory, call: &str, tool: &str, error: bool, details: Value) {
        history.observe(&event(LiveEventBody::ToolStarted(ToolStarted {
            turn_id: TurnId::new("turn:test").unwrap(),
            tool: ToolUseBlock {
                tool_use_id: call.into(),
                capability_id: CapabilityId::new(tool).unwrap(),
                arguments: json!({}),
            },
            intent: None,
        })));
        history.observe(&event(LiveEventBody::ToolFinished(ToolFinished {
            turn_id: TurnId::new("turn:test").unwrap(),
            result: ToolResultBlock {
                tool_use_id: call.into(),
                is_error: error,
                content: vec![LiveContentBlock::Text(
                    "redo and failed check are not typed evidence".into(),
                )],
                details: Some(details),
            },
        })));
    }

    #[test]
    fn repeated_distinct_typed_failures_buy_only_one_rung() {
        let mut history = RouteHistory::default();
        result(
            &mut history,
            "one",
            "test.run",
            true,
            json!({"details":{"errorKind":"arguments"}}),
        );
        assert!(history.warrant.is_none());
        result(
            &mut history,
            "one",
            "test.run",
            true,
            json!({"details":{"errorKind":"arguments"}}),
        );
        assert!(
            history.warrant.is_none(),
            "replay is not a second failed call"
        );
        result(
            &mut history,
            "two",
            "test.run",
            true,
            json!({"details":{"errorKind":"arguments"}}),
        );
        let warrant = history.warrant.clone().expect("real repeated failure");
        history.observe(&event(LiveEventBody::ModelRouted(ModelRouted {
            command_id: CommandId::new("class-route:test").unwrap(),
            provider: "gateway".into(),
            model: "grok".into(),
            applied: true,
            decision: ClassRouteDecision {
                from_class: "fast".into(),
                to_class: next_class("fast").unwrap().into(),
                warrant: Some(warrant),
                through: EventSeq::new(1),
                owner_message: None,
                refusal: None,
            },
        })));
        assert_eq!(history.class.as_deref(), Some("standard"));
        assert_eq!(history.model.as_deref(), Some("grok"));
        assert!(
            history.warrant.is_none(),
            "the same batch cannot cascade to strong"
        );
        assert!(next_class("strong").unwrap_err().contains("ceiling"));
    }

    #[test]
    fn context_refusals_do_not_hold_an_account() {
        assert!(refusing_fault("context size has been exceeded", None).is_none());
        assert!(refusing_fault("request failed", Some(500)).is_none());
        assert!(refusing_fault("request failed", Some(401)).is_some());
    }
}
