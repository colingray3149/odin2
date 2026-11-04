//! Terminal surface over the same authenticated Huginn worker and durable plan gate.
//! No tool execution, credentials, or alternate model runtime lives in this client.
mod decisions;

use odin_cli::authority_provision::{SessionComposition, MAX_PROMPT_FILE_BYTES};
use odin_cli::operator_prompt::{self, OperatorIdentity};
use odin_domain::huginn as live;
use odin_huginn::client::EndpointTransport;
use odin_huginn::OdindConfig;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::Duration;
use time::OffsetDateTime;

use self::decisions::{
    render_kernel_pending, try_owner_decision, OwnerDecisionContext, PendingDecision,
};
use super::transport::{
    abort_current_epoch, find_live_session, generated_command_id, live_request_id, send_prompt,
    Client, CLEANUP_BUDGET, LIVE_PAGE_LIMIT, LIVE_REQUEST_TIMEOUT,
};

/// How long the chat waits for a typed line before it polls history again.
const INPUT_POLL: Duration = Duration::from_millis(500);

/// Opened sessions validate composition; attached sessions use the recorded bridge run.
pub(super) enum PlanGate<'a> {
    Opened(&'a SessionComposition),
    Attached {
        seat: String,
        lane: odin_domain::LaneId,
    },
}

impl PlanGate<'_> {
    fn seat(&self) -> &str {
        match self {
            Self::Opened(composition) => composition.seat.as_str(),
            Self::Attached { seat, .. } => seat,
        }
    }

    /// Attach has no local project declaration, so omit its banner label.
    fn project(&self) -> Option<String> {
        match self {
            Self::Opened(composition) => Some(composition.project.to_string()),
            Self::Attached { .. } => None,
        }
    }
}

pub(super) struct InteractiveSession<'a> {
    pub(super) runtime: &'a tokio::runtime::Runtime,
    pub(super) client: &'a Client,
    pub(super) config: &'a OdindConfig,
    pub(super) gate: PlanGate<'a>,
    pub(super) summary: &'a live::LiveSessionSummary,
    pub(super) identity: &'a OperatorIdentity,
    /// Attach mode: quitting DETACHES — no Abort is ever sent and the
    /// governed session keeps running under the controller.
    pub(super) attach: bool,
    /// The explicit Zellij session name registered as the terminal tab
    /// target before the chat loop. Read from the CLIENT's own
    /// environment; the daemon never reads env.
    pub(super) zellij_session: Option<String>,
}

pub(super) fn run(
    session: &InteractiveSession,
    mut accepted: bool,
    output: &mut dyn Write,
) -> Result<(), String> {
    let InteractiveSession {
        runtime,
        client,
        summary,
        attach,
        ..
    } = *session;
    let stop = Arc::new(AtomicBool::new(false));
    let mut registrations = Vec::new();
    for signal in [
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ] {
        registrations.push(
            signal_hook::flag::register(signal, Arc::clone(&stop)).map_err(|e| e.to_string())?,
        );
    }
    let mut epoch = summary.epoch;
    let result = interact(session, &mut accepted, &stop, output, &mut epoch);
    if attach {
        // Detach, never abort: the governed session keeps running under
        // the controller, and `odin session --attach <id>` returns to it.
        for registration in registrations {
            signal_hook::low_level::unregister(registration);
        }
        writeln!(
            output,
            "\nDetached from session {}; it keeps running (reattach with `odin session \
             --attach {}`).",
            summary.session_id, summary.session_id
        )
        .map_err(io_error)?;
        return result;
    }
    // Restart advances the controller epoch after attach. Abort must use
    // that current fact, not the attach-time snapshot. The whole refetch,
    // send, and one mismatch retry share one deadline. The helpers await
    // the client directly so this block_on does not nest.
    let mut abort_epoch = epoch;
    let mut abort_state = summary.state;
    let cleanup = runtime.block_on(async {
        match tokio::time::timeout(
            CLEANUP_BUDGET,
            abort_current_epoch(
                client,
                summary.session_id,
                &mut abort_epoch,
                &mut abort_state,
                output,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err("session cleanup timed out".to_owned()),
        }
    });
    for registration in registrations {
        signal_hook::low_level::unregister(registration);
    }
    match cleanup {
        Ok(()) => {
            let _ = writeln!(
                output,
                "\nSession closed; stop requested. History is retained."
            );
        }
        Err(error) => {
            return Err(format!(
                "Session closed but its cleanup needs attention: {error}"
            ));
        }
    }
    result
}

fn interact(
    session: &InteractiveSession,
    accepted: &mut bool,
    stop: &AtomicBool,
    output: &mut dyn Write,
    epoch: &mut live::SessionEpoch,
) -> Result<(), String> {
    let InteractiveSession {
        runtime,
        client,
        config,
        gate,
        summary,
        identity,
        attach,
        zellij_session,
    } = session;
    match gate.project() {
        Some(project) => writeln!(
            output,
            "Project: {}  Lane: {}  Session: {}",
            project,
            gate_lane(gate),
            summary.session_id
        ),
        None => writeln!(
            output,
            "Lane: {}  Session: {} (existing session, attached)",
            gate_lane(gate),
            summary.session_id
        ),
    }
    .map_err(io_error)?;
    writeln!(
        output,
        "\x1b[1;36m{} · OMP · {}/{}\x1b[0m",
        gate.seat(),
        summary.provider,
        summary.model
    )
    .map_err(io_error)?;
    writeln!(output, "Permissions: declared capsule tools; project-scoped files/shell; consequential actions require approval.").map_err(io_error)?;
    if *attach {
        writeln!(
            output,
            "Type a prompt then Enter. /status · /quit · Ctrl-C DETACH; the session keeps \
             running.\n"
        )
    } else {
        writeln!(
            output,
            "Type a prompt then Enter. /status · /quit · Ctrl-C closes this session and its \
             workers.\n"
        )
    }
    .map_err(io_error)?;
    let (sender, receiver) = mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        while let Ok(Some(line)) = read_bounded_line(&mut input, MAX_PROMPT_FILE_BYTES + 1) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut connection = runtime
        .block_on(client.connect())
        .map_err(|e| e.to_string())?;
    register_terminal_target(runtime, &mut connection, zellij_session.clone(), output)?;
    let mut after = live::EventSeq::new(0);
    let mut state = summary.state;
    let mut streamed = false;
    let mut prompt_visible = false;
    let mut live_pending: BTreeMap<String, (live::SessionEpoch, live::PermissionRequest)> =
        BTreeMap::new();
    let mut shown_kernel: BTreeMap<String, PendingDecision> = BTreeMap::new();
    let mut restart_sent = false;
    let ledger_path = config.paths.state_root.join("ledger.sqlite3");
    render_kernel_pending(&ledger_path, summary.session_id, &mut shown_kernel, output)?;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let request_id = live::RequestId::parse(&generated_command_id()?.to_string())
            .map_err(|e| e.to_string())?;
        let response = runtime
            .block_on(async {
                tokio::time::timeout(
                    LIVE_REQUEST_TIMEOUT,
                    connection.request_live(live::LiveClientRequest::GetHistory {
                        request_id,
                        session_id: summary.session_id,
                        after,
                        limit: LIVE_PAGE_LIMIT,
                    }),
                )
                .await
            })
            .map_err(|error| format!("history request timed out: {error}"))?
            .map_err(|e| e.to_string())?;
        let live::LiveResponse::History(page) = response else {
            return Err("unexpected history response".to_owned());
        };
        for event in page.events {
            after = event.sequence;
            if event.epoch > *epoch {
                let refreshed = find_live_session(runtime, client, summary.session_id)?;
                if refreshed.epoch != *epoch {
                    live_pending.clear();
                }
                *epoch = refreshed.epoch;
                state = refreshed.state;
            }
            match event.body {
                live::LiveEventBody::AssistantDelta(delta) => {
                    write!(output, "{}", safe_text(&delta.text)).map_err(io_error)?;
                    streamed = true;
                    prompt_visible = false;
                }
                live::LiveEventBody::AssistantMessage(message) => {
                    if !streamed {
                        render_blocks(&message.content, output)?;
                    }
                    writeln!(output).map_err(io_error)?;
                    streamed = false;
                    prompt_visible = false;
                }
                live::LiveEventBody::ToolStarted(tool) => {
                    writeln!(
                        output,
                        "\n\x1b[36m[tool {}]\x1b[0m",
                        tool.tool.capability_id
                    )
                    .map_err(io_error)?;
                    let args =
                        serde_json::to_string(&tool.tool.arguments).map_err(|e| e.to_string())?;
                    writeln!(
                        output,
                        "{}",
                        safe_text(&args.chars().take(400).collect::<String>())
                    )
                    .map_err(io_error)?;
                    prompt_visible = false;
                }
                live::LiveEventBody::ToolFinished(tool) => {
                    writeln!(
                        output,
                        "[tool {}]",
                        if tool.result.is_error {
                            "failed"
                        } else {
                            "finished"
                        }
                    )
                    .map_err(io_error)?;
                    render_blocks(&tool.result.content, output)?;
                    // A failed dispatch is exactly where the kernel's R3
                    // gate can have minted a durable request: surface any
                    // not-yet-shown row right under the failure.
                    if tool.result.is_error {
                        render_kernel_pending(
                            &ledger_path,
                            summary.session_id,
                            &mut shown_kernel,
                            output,
                        )?;
                    }
                }
                live::LiveEventBody::SessionStateChanged(change) if event.epoch == *epoch => {
                    state = change.current;
                    writeln!(output, "\n[{state:?}]").map_err(io_error)?;
                    // An ended session's client leaves, so its tab closes.
                    if state == live::LiveSessionState::Ended {
                        return Ok(());
                    }
                    prompt_visible = false;
                    // An attached tab watches work Odin delegated: its owner sees the
                    // failure and reports it, so restarting here would hide it.
                    if state == live::LiveSessionState::Failed && *attach {
                        writeln!(
                            output,
                            "[failed] the provider failed this turn; Odin reports it to the \
                             seat that delegated this work. Send Restart to continue here."
                        )
                        .map_err(io_error)?;
                    } else if state == live::LiveSessionState::Failed && !restart_sent {
                        restart_sent = true;
                        writeln!(
                            output,
                            "[failed] the provider failed this turn. Restarting the session; if \
                             it stays failed, send Restart."
                        )
                        .map_err(io_error)?;
                        if let Err(error) = send_command_recovering(
                            runtime,
                            client,
                            summary.session_id,
                            epoch,
                            &mut state,
                            output,
                            |epoch, _state, _fresh| {
                                Ok(live::LiveCommand {
                                    command_id: generated_command_id()?,
                                    session_id: summary.session_id,
                                    expected_epoch: epoch,
                                    expected_event_head: None,
                                    body: live::LiveCommandBody::Restart,
                                })
                            },
                        ) {
                            writeln!(
                                output,
                                "[failed] restart was not accepted ({error}). Send Restart to \
                                 continue."
                            )
                            .map_err(io_error)?;
                        }
                    }
                    if state != live::LiveSessionState::Failed {
                        restart_sent = false;
                    }
                    if state == live::LiveSessionState::Idle {
                        render_kernel_pending(
                            &ledger_path,
                            summary.session_id,
                            &mut shown_kernel,
                            output,
                        )?;
                    }
                }
                live::LiveEventBody::Error(error) => {
                    writeln!(
                        output,
                        "\n[error {}] {}",
                        safe_text(&error.code),
                        safe_text(&error.message)
                    )
                    .map_err(io_error)?;
                }
                live::LiveEventBody::PermissionRequested(permission)
                    if event.epoch == *epoch
                        && permission.expires_at > OffsetDateTime::now_utc() =>
                {
                    writeln!(
                        output,
                        "\n[approval required: {}] {}",
                        permission.capability_id,
                        safe_text(&permission.prompt)
                    )
                    .map_err(io_error)?;
                    output.flush().map_err(io_error)?;
                    live_pending
                        .insert(permission.request_id.to_string(), (event.epoch, permission));
                }
                live::LiveEventBody::PermissionResolved(resolution) if event.epoch == *epoch => {
                    live_pending.remove(&resolution.request_id.to_string());
                }
                live::LiveEventBody::ControlCompleted(live::CommandOutcome::Failed {
                    error,
                    ..
                }) => {
                    writeln!(output, "\n[control failed] {}", safe_text(&error.message))
                        .map_err(io_error)?;
                }
                live::LiveEventBody::SessionClosed(_) => return Ok(()),
                _ => {}
            }
        }
        if after < page.head {
            continue;
        }
        if !prompt_visible && state == live::LiveSessionState::Idle {
            write!(output, "\n{}> ", gate.seat()).map_err(io_error)?;
            prompt_visible = true;
        }
        output.flush().map_err(io_error)?;
        match receiver.recv_timeout(INPUT_POLL) {
            Ok(line) => {
                let text = line.trim();
                if text == "/quit" || text == "/exit" {
                    break;
                }
                if text == "/status" {
                    writeln!(
                        output,
                        "{} · {} · {}/{} · {:?} · epoch {}",
                        summary.session_id,
                        gate.seat(),
                        summary.provider,
                        summary.model,
                        state,
                        epoch.get()
                    )
                    .map_err(io_error)?;
                    prompt_visible = false;
                    continue;
                }
                // Explicit decisions resolve pending approvals rather than reaching the assistant.
                if try_owner_decision(
                    OwnerDecisionContext {
                        runtime,
                        client,
                        ledger_path: &ledger_path,
                        session_id: summary.session_id,
                        epoch: *epoch,
                        live_pending: &live_pending,
                        shown_kernel: &shown_kernel,
                    },
                    text,
                    output,
                )? {
                    prompt_visible = false;
                    continue;
                }
                if text.is_empty() {
                    continue;
                }
                if text.len() as u64 > MAX_PROMPT_FILE_BYTES {
                    writeln!(output, "Prompt too large.").map_err(io_error)?;
                    continue;
                }
                let body = match message_body(state, text) {
                    Ok(body) => body,
                    Err(note) => {
                        writeln!(output, "[not sent] {note}").map_err(io_error)?;
                        continue;
                    }
                };
                // A running session keeps the plan its owner accepted: only a Prompt
                // starting a turn needs one, and an attached session may already hold it.
                let mut first_prompt =
                    !*accepted && matches!(body, live::LiveCommandBody::Prompt { .. });
                if first_prompt
                    && matches!(gate, PlanGate::Attached { .. })
                    && operator_prompt::session_plan_accepted(config, &summary.session_id)?
                {
                    *accepted = true;
                    first_prompt = false;
                }
                let mut gated: Option<live::LiveCommand> = None;
                if first_prompt {
                    // The SAME acceptance owner as the opened path: the
                    // exact prompt becomes the durably accepted plan of
                    // the session's real bridge run before any command
                    // exists.
                    let prepared = match gate {
                        PlanGate::Opened(composition) => operator_prompt::prepare(
                            config,
                            composition,
                            identity.device_id,
                            text,
                            *epoch,
                        ),
                        PlanGate::Attached { .. } => operator_prompt::prepare_existing(
                            config,
                            &summary.session_id,
                            identity.device_id,
                            text,
                            *epoch,
                        ),
                    }?;
                    let (command, _receipt) = prepared.into_parts();
                    gated = Some(command);
                    *accepted = true;
                }
                // A refused message is reported and the session carries on; a dead
                // controller ends the chat at the next history request.
                if let Err(error) = send_command_recovering(
                    runtime,
                    client,
                    summary.session_id,
                    epoch,
                    &mut state,
                    output,
                    |epoch, state, fresh_id| {
                        if let Some(prepared) = gated.as_ref() {
                            // The plan-gated first prompt is idempotent
                            // under its accepted command id; only an
                            // epoch-rejected attempt — which applied
                            // nothing — takes a fresh identity on retry.
                            let mut command = prepared.clone();
                            command.expected_epoch = epoch;
                            if fresh_id {
                                command.command_id = generated_command_id()?;
                            }
                            Ok(command)
                        } else {
                            Ok(live::LiveCommand {
                                command_id: generated_command_id()?,
                                session_id: summary.session_id,
                                expected_epoch: epoch,
                                expected_event_head: None,
                                body: message_body(state, text)?,
                            })
                        }
                    },
                ) {
                    writeln!(output, "[not sent] {error}").map_err(io_error)?;
                }
                prompt_visible = false;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    Ok(())
}

/// One line from `input`, keeping at most `limit` bytes of it: the rest of a longer line is
/// read and dropped, so an over-long paste reaches the chat as one over-long line, never as a
/// head and a second line made of its tail. `None` at end of input.
fn read_bounded_line(input: &mut impl BufRead, limit: u64) -> std::io::Result<Option<String>> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut line = Vec::new();
    let mut read_any = false;
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        read_any = true;
        let (chunk, line_ended) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(end) => (&buffer[..=end], true),
            None => (buffer, false),
        };
        let room = limit.saturating_sub(line.len());
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        let used = chunk.len();
        input.consume(used);
        if line_ended {
            break;
        }
    }
    Ok(read_any.then(|| String::from_utf8_lossy(&line).into_owned()))
}

/// The command that carries a typed message: the controller applies a Prompt to an idle
/// session and a FollowUp to a running one, and refuses either elsewhere.
fn message_body(
    state: live::LiveSessionState,
    text: &str,
) -> Result<live::LiveCommandBody, String> {
    let message = live::LiveMessage::new(vec![live::LiveContentBlock::Text(text.to_owned())])
        .map_err(|error| error.to_string())?;
    let owner_text = Some(text.to_owned());
    match state {
        live::LiveSessionState::Idle => Ok(live::LiveCommandBody::Prompt {
            message,
            owner_text,
        }),
        live::LiveSessionState::Running | live::LiveSessionState::RequiresAction => {
            Ok(live::LiveCommandBody::FollowUp {
                message,
                owner_text,
            })
        }
        other => Err(format!(
            "the session is {other:?}; type again when it is idle or running"
        )),
    }
}

fn io_error(error: std::io::Error) -> String {
    error.to_string()
}

fn gate_lane(gate: &PlanGate<'_>) -> String {
    match gate {
        PlanGate::Opened(composition) => composition.lane.to_string(),
        PlanGate::Attached { lane, .. } => lane.to_string(),
    }
}

/// Sends one live session command, recovering exactly once from a
/// controller-side epoch advance (a daemon restart or ownership reclaim
/// between attach and send). A command rejected for its epoch was
/// validated before journaling and applied nothing, so recovery is
/// lawful: adopt the controller's CURRENT session fact — refetched from
/// the authoritative session list, never inferred from replayed history —
/// and send one fresh command, because the journaled rejection replays
/// forever under the rejected command's id. `build` receives the
/// operating epoch and session state, and whether the previous command
/// identity was consumed by the rejection.
fn send_command_recovering(
    runtime: &tokio::runtime::Runtime,
    client: &Client,
    session_id: live::LiveSessionId,
    epoch: &mut live::SessionEpoch,
    state: &mut live::LiveSessionState,
    output: &mut dyn Write,
    mut build: impl FnMut(
        live::SessionEpoch,
        live::LiveSessionState,
        bool,
    ) -> Result<live::LiveCommand, String>,
) -> Result<(), String> {
    let receipt = send_prompt(runtime, client, build(*epoch, *state, false)?)?;
    let receipt = match receipt {
        live::CommandReceipt::Accepted { .. } => return Ok(()),
        live::CommandReceipt::Rejected {
            reason: live::CommandRejection::EpochMismatch { .. },
            ..
        } => {
            let refreshed = find_live_session(runtime, client, session_id)?;
            writeln!(
                output,
                "\n[epoch {} → {}] the controller reclaimed this session while it was \
                 attached; recovered the current session fact and resending",
                epoch.get(),
                refreshed.epoch.get()
            )
            .map_err(io_error)?;
            *epoch = refreshed.epoch;
            *state = refreshed.state;
            send_prompt(runtime, client, build(*epoch, *state, true)?)?
        }
        other => {
            return Err(format!(
                "the controller did not accept the command: {other:?}"
            ))
        }
    };
    match receipt {
        live::CommandReceipt::Accepted { .. } => Ok(()),
        other => Err(format!(
            "the controller did not accept the command: {other:?}"
        )),
    }
}

/// Registers this client's explicit Zellij session name as the terminal
/// tab target before the chat loop. The daemon never reads the
/// environment: only this validated explicit name crosses the wire. The
/// outcome is reported once; a typed refusal is a visible warning and
/// never kills the chat.
fn register_terminal_target(
    runtime: &tokio::runtime::Runtime,
    connection: &mut odin_huginn::client::LiveConnection<
        odin_huginn::client::EndpointSocket,
        EndpointTransport,
    >,
    zellij_session: Option<String>,
    output: &mut dyn Write,
) -> Result<(), String> {
    let Some(name) = zellij_session else {
        return Ok(());
    };
    let request_id = live_request_id()?;
    let response = runtime.block_on(async {
        tokio::time::timeout(
            LIVE_REQUEST_TIMEOUT,
            connection.request_live(live::LiveClientRequest::BindTerminalTarget {
                request_id,
                zellij_session: name.clone(),
            }),
        )
        .await
    });
    let note = match response {
        Ok(Ok(live::LiveResponse::TerminalTarget(status))) => {
            match serde_json::to_string(&status) {
                Ok(rendered) => format!("registered: {rendered}"),
                Err(error) => format!("registered (status unrenderable: {error})"),
            }
        }
        Ok(Ok(other)) => format!("unexpected controller answer: {other:?}"),
        Ok(Err(error)) => format!("refused: {error}"),
        Err(_) => "refused: the request timed out".to_owned(),
    };
    writeln!(output, "[terminal target] {note}").map_err(io_error)
}

// Model/tool text is untrusted: never interpret escape sequences as terminal commands.
fn safe_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

fn render_blocks(blocks: &[live::LiveContentBlock], output: &mut dyn Write) -> Result<(), String> {
    for block in blocks {
        if let live::LiveContentBlock::Text(text) = block {
            let parsed = serde_json::from_str::<serde_json::Value>(text).ok();
            let readable = parsed.as_ref().and_then(|value| {
                if let Some(content) = value.get("content").and_then(serde_json::Value::as_str) {
                    return Some(content.to_owned());
                }
                let content = value.get("content")?.as_array()?;
                let texts = content
                    .iter()
                    .filter_map(|block| block.get("text")?.as_str())
                    .collect::<Vec<_>>();
                (!texts.is_empty()).then(|| texts.join("\n"))
            });
            let bounded: String = readable
                .as_deref()
                .unwrap_or(text)
                .chars()
                .take(6000)
                .collect();
            writeln!(output, "{}", safe_text(&bounded)).map_err(io_error)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_text_cannot_inject_control_sequences() {
        assert_eq!(
            super::safe_text("hello\x1b]52;c;payload\x07\r\nworld"),
            "hello]52;c;payload\nworld"
        );
    }

    #[test]
    fn a_message_is_a_prompt_when_idle_a_follow_up_when_running_and_not_sent_otherwise() {
        use live::LiveCommandBody as Body;
        use live::LiveSessionState as State;
        assert!(matches!(
            message_body(State::Idle, "hi"),
            Ok(Body::Prompt { .. })
        ));
        for running in [State::Running, State::RequiresAction] {
            assert!(matches!(
                message_body(running, "hi"),
                Ok(Body::FollowUp { .. })
            ));
        }
        for waiting in [
            State::Starting,
            State::Failed,
            State::Detached,
            State::Ended,
        ] {
            assert!(message_body(waiting, "hi").is_err(), "{waiting:?}");
        }
    }
}
