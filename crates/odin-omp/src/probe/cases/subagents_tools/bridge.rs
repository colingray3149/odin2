//! Case 13 bridge leg: the journaled bridge round trip, side-channel
//! correlation, and journal validation behind the host-tool case.

use super::shared::*;
use super::*;

pub(super) struct BridgeCommandIds {
    host_tool: String,
    scoped_uri: String,
}

pub(super) async fn exercise_bridge(
    context: &CaseContext,
    bridge: &OmpBridge,
    receiver: &mut broadcast::Receiver<ObservedFrame>,
) -> Result<BridgeCommandIds, String> {
    let host_tool = bridge
        .prompt(Prompt::text(format!(
            "odin-mock:host-tool {}",
            context.ids().lane
        )))
        .await
        .map_err(|error| error.to_string())?;
    if directive_rejected(&host_tool.data) {
        return Err("host-tool response explicitly reported agentInvoked=false".to_owned());
    }
    wait_for_bridge_agent_end(receiver).await?;

    let scoped_uri = bridge
        .prompt(Prompt::text(format!(
            "odin-mock:read lane://{}",
            context.ids().lane
        )))
        .await
        .map_err(|error| error.to_string())?;
    if directive_rejected(&scoped_uri.data) {
        return Err("scoped-URI response explicitly reported agentInvoked=false".to_owned());
    }
    wait_for_bridge_agent_end(receiver).await?;

    Ok(BridgeCommandIds {
        host_tool: host_tool.command_id.to_string(),
        scoped_uri: scoped_uri.command_id.to_string(),
    })
}

async fn wait_for_bridge_agent_end(
    receiver: &mut broadcast::Receiver<ObservedFrame>,
) -> Result<(), String> {
    let deadline = operation_deadline();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("bridge agent_end wait reached its deadline".to_owned());
        }
        let observed = tokio::time::timeout(remaining, receiver.recv())
            .await
            .map_err(|_| "bridge agent_end wait reached its deadline".to_owned())?
            .map_err(|error| match error {
                broadcast::error::RecvError::Closed => {
                    "bridge observation channel closed before agent_end".to_owned()
                }
                broadcast::error::RecvError::Lagged(count) => {
                    format!("bridge observation receiver lagged by {count} frames")
                }
            })?;
        if observed
            .value()
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            == Some("agent_end")
        {
            return Ok(());
        }
    }
}

pub(super) struct BridgeCorrelation {
    host_request: String,
    uri_request: String,
}

pub(super) fn validate_bridge_side_channels(
    context: &CaseContext,
    uri_router: &ScopedUriRouter,
    observations: &[ObservedFrame],
    dropped_observations: u64,
    side_channels: &[SideChannelOutcome],
    dropped_side_channels: u64,
) -> Result<BridgeCorrelation, String> {
    if dropped_observations != 0 || dropped_side_channels != 0 {
        return Err(format!(
            "bounded evidence windows dropped {dropped_observations} observations and \
             {dropped_side_channels} side-channel outcomes"
        ));
    }
    let host_frames = observations
        .iter()
        .filter(|observed| {
            observed.class == FrameClass::HostTool
                && observed
                    .value()
                    .and_then(|value| value.get("type"))
                    .and_then(Value::as_str)
                    == Some("host_tool_call")
                && observed
                    .value()
                    .and_then(|value| value.get("toolName"))
                    .and_then(Value::as_str)
                    == Some(LaneStatusTool::NAME)
        })
        .collect::<Vec<_>>();
    if host_frames.len() != 1 {
        return Err(format!(
            "expected one lane-status host call, observed {}",
            host_frames.len()
        ));
    }
    let uri = format!("lane://{}", context.ids().lane);
    let uri_frames = observations
        .iter()
        .filter(|observed| {
            observed.class == FrameClass::HostUri
                && observed
                    .value()
                    .and_then(|value| value.get("type"))
                    .and_then(Value::as_str)
                    == Some("host_uri_request")
                && observed
                    .value()
                    .and_then(|value| value.get("url"))
                    .and_then(Value::as_str)
                    == Some(uri.as_str())
        })
        .collect::<Vec<_>>();
    if uri_frames.len() != 1 {
        return Err(format!(
            "expected one bound-lane scoped URI request, observed {}",
            uri_frames.len()
        ));
    }
    let host_request = request_id(host_frames[0])?;
    let uri_request = request_id(uri_frames[0])?;
    let host_outcome = unique_side_channel(side_channels, &host_request)?;
    if host_outcome.kind != SideChannelKind::Tool || host_outcome.name != LaneStatusTool::NAME {
        return Err("lane-status request correlated to the wrong side channel".to_owned());
    }
    let host_result = completed_side_result(host_outcome)?;
    if host_result
        .pointer("/details/laneId")
        .and_then(Value::as_str)
        != Some(context.ids().lane.as_str())
        || host_result
            .pointer("/details/status")
            .and_then(Value::as_str)
            != Some("running")
        || host_result
            .pointer("/details/backend")
            .and_then(Value::as_str)
            != Some("local_omp")
    {
        return Err("lane-status host result did not return the bound running lane".to_owned());
    }

    let uri_outcome = unique_side_channel(side_channels, &uri_request)?;
    if uri_outcome.kind != SideChannelKind::Uri || uri_outcome.name != uri {
        return Err("scoped URI request correlated to the wrong side channel".to_owned());
    }
    let uri_result = completed_side_result(uri_outcome)?;
    if uri_result.get("immutable").and_then(Value::as_bool) != Some(true)
        || uri_result.get("contentType").and_then(Value::as_str) != Some("application/json")
    {
        return Err("scoped URI result lost its immutable JSON contract".to_owned());
    }
    if uri_result.get("notes").is_some() {
        return Err("lane URI result carried non-canonical resolver notes".to_owned());
    }
    let content = uri_result
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| "scoped URI result omitted content".to_owned())?;
    let lane: Value = serde_json::from_str(content).map_err(|error| error.to_string())?;
    // Resolve the same URL through the same router and bound scope the bridge
    // dispatches with: the round trip only completes when the lane's session
    // propagation proves scope, and byte equality pins the exact snapshot.
    let canonical = match uri_router
        .resolve(&UriContext::new(context.scope()), &uri)
        .map_err(|error| format!("bound-lane URI refused the bound scope: {error}"))?
        .body
    {
        UriBody::Json(value) => value,
        UriBody::Bytes(_) => return Err("bound-lane URI resolved to a non-JSON body".to_owned()),
    };
    let canonical = serde_json::to_string(&canonical).map_err(|error| error.to_string())?;
    if content != canonical {
        return Err("lane URI content differed from the scoped canonical lane snapshot".to_owned());
    }
    let run = context.ids().run.to_string();
    let session = context.ids().session.to_string();
    if lane.get("laneId").and_then(Value::as_str) != Some(context.ids().lane.as_str())
        || lane.get("status").and_then(Value::as_str) != Some("running")
        || lane.get("backend").and_then(Value::as_str) != Some("local_omp")
        || lane.get("seatId").and_then(Value::as_str) != Some(context.ids().seat.as_str())
        || lane.get("sessionRef").and_then(Value::as_str) != Some(session.as_str())
        || lane.get("currentRunId").and_then(Value::as_str) != Some(run.as_str())
    {
        return Err("lane URI snapshot was not the bound running lane".to_owned());
    }
    Ok(BridgeCorrelation {
        host_request,
        uri_request,
    })
}

fn unique_side_channel<'a>(
    outcomes: &'a [SideChannelOutcome],
    request_id: &str,
) -> Result<&'a SideChannelOutcome, String> {
    let matches = outcomes
        .iter()
        .filter(|outcome| outcome.request_id == request_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "request {request_id} produced {} terminal outcomes",
            matches.len()
        ));
    }
    Ok(matches[0])
}

fn completed_side_result(outcome: &SideChannelOutcome) -> Result<&Value, String> {
    match &outcome.status {
        SideChannelStatus::Completed { result, sent: true } => Ok(result),
        SideChannelStatus::Completed { sent: false, .. } => Err(format!(
            "request {} completed but was not sent",
            outcome.request_id
        )),
        SideChannelStatus::Cancelled { .. } => Err(format!(
            "request {} was unexpectedly cancelled",
            outcome.request_id
        )),
        SideChannelStatus::Failed { error } => Err(format!(
            "request {} failed instead of completing: {error}",
            outcome.request_id
        )),
    }
}

pub(super) fn journal_snapshot(context: &CaseContext) -> Result<(Vec<Value>, Vec<u8>), String> {
    let shared = context.ledger();
    let ledger = shared
        .lock()
        .map_err(|_| "case ledger mutex was poisoned".to_owned())?;
    let head = ledger
        .reconnect_head(&context.ids().session)
        .map_err(|error| error.to_string())?;
    let events = ledger
        .live_event_history(&context.ids().session, 0, head)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|event| {
            json!({
                "eventId": event.event_id.to_string(),
                "sessionId": event.session_id.to_string(),
                "epoch": event.epoch,
                "sequence": event.sequence,
                "occurredAt": event.occurred_at.to_string(),
                "body": event.body,
                "blobRefs": event.blob_refs,
            })
        })
        .collect::<Vec<_>>();
    if events.is_empty() {
        return Err("bridge live-event journal was empty".to_owned());
    }
    let bytes = serde_json::to_vec_pretty(&events).map_err(|error| error.to_string())?;
    Ok((events, bytes))
}

pub(super) fn validate_journal(
    journal: &[Value],
    commands: &BridgeCommandIds,
    correlation: &BridgeCorrelation,
) -> Result<(), String> {
    for command_id in [&commands.host_tool, &commands.scoped_uri] {
        for kind in ["command_issued", "command_response"] {
            if !journal.iter().any(|event| {
                event.pointer("/body/kind").and_then(Value::as_str) == Some(kind)
                    && event.pointer("/body/command_id").and_then(Value::as_str)
                        == Some(command_id.as_str())
            }) {
                return Err(format!(
                    "journal omitted {kind} for bridge command {command_id}"
                ));
            }
        }
    }
    for (request_id, channel) in [
        (&correlation.host_request, "tool"),
        (&correlation.uri_request, "uri"),
    ] {
        if !journal.iter().any(|event| {
            event.pointer("/body/kind").and_then(Value::as_str) == Some("side_channel_outcome")
                && event.pointer("/body/request_id").and_then(Value::as_str)
                    == Some(request_id.as_str())
                && event.pointer("/body/channel").and_then(Value::as_str) == Some(channel)
                && event
                    .pointer("/body/status/outcome")
                    .and_then(Value::as_str)
                    == Some("completed")
                && event.pointer("/body/status/sent").and_then(Value::as_bool) == Some(true)
        }) {
            return Err(format!(
                "journal omitted the sent {channel} outcome for request {request_id}"
            ));
        }
    }
    Ok(())
}

pub(super) fn side_channel_bytes(
    outcomes: &[SideChannelOutcome],
    dropped: u64,
) -> Result<Vec<u8>, String> {
    let values = outcomes
        .iter()
        .map(|outcome| {
            let status = match &outcome.status {
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
            };
            json!({
                "requestId": outcome.request_id,
                "kind": match outcome.kind {
                    SideChannelKind::Tool => "tool",
                    SideChannelKind::Uri => "uri",
                },
                "name": outcome.name,
                "status": status,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec_pretty(&json!({
        "dropped": dropped,
        "outcomes": values,
    }))
    .map_err(|error| error.to_string())
}
