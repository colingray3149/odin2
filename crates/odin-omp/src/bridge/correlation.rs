//! Command correlation and queued replies: pending reply waiters,
//! in-flight turn anchors, the pump message queue, and the wire request
//! id stamp.

use super::*;

pub(super) struct PendingReply {
    pub(super) command: String,
    pub(super) command_id: CommandId,
    pub(super) reply: oneshot::Sender<Result<Value, BridgeError>>,
    /// How this dispatch consumes its correlated response failure, chosen
    /// at registration — before the wire write, never from receiver
    /// timing. Awaited dispatches deliver through the waiter; observed
    /// (open-loop) dispatches own no waiter, so typed failures ride the
    /// observed frame.
    pub(super) delivery: ReplyDelivery,
}

/// How one dispatched command's correlated response failure reaches its
/// consumer. Chosen at dispatch time: [`ReplyDelivery::Awaited`] paths
/// deliver through the response waiter; [`ReplyDelivery::Observed`] — the
/// open-loop prompt dispatch — drops its waiter at the write-acknowledged
/// dispatch, so a typed correlated failure must be annotated on the
/// observed frame for the session journal, deterministically and
/// independent of whether the response beat the receiver drop.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum ReplyDelivery {
    Awaited,
    Observed,
}

pub(super) struct DispatchedCommand {
    pub(super) command_id: CommandId,
    pub(super) reply: oneshot::Receiver<Result<Value, BridgeError>>,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum InFlightKind {
    Mutating,
    Informational,
}

struct InFlight {
    command_id: CommandId,
    command: String,
    kind: InFlightKind,
}

#[derive(Default)]
pub(super) struct Correlation {
    pending: HashMap<String, PendingReply>,
    in_flight: Vec<InFlight>,
}

impl Correlation {
    pub(super) fn register(
        &mut self,
        wire_id: String,
        command: &str,
        command_id: CommandId,
        reply: oneshot::Sender<Result<Value, BridgeError>>,
        kind: InFlightKind,
        delivery: ReplyDelivery,
    ) -> bool {
        if self.pending.contains_key(&wire_id) {
            let _ = reply.send(Err(BridgeError::Config {
                detail: format!("wire request id `{wire_id}` is already pending"),
            }));
            return false;
        }
        let previous = self.pending.insert(
            wire_id,
            PendingReply {
                command: command.to_owned(),
                command_id: command_id.clone(),
                reply,
                delivery,
            },
        );
        debug_assert!(previous.is_none());
        self.in_flight.push(InFlight {
            command_id,
            command: command.to_owned(),
            kind,
        });
        true
    }

    /// Takes only the immediate response waiter. Semantic turn correlation is
    /// retained until `finish_response` or a terminal lifecycle frame.
    pub(super) fn take_pending(&mut self, wire_id: &str) -> Option<PendingReply> {
        self.pending.remove(wire_id)
    }

    /// Cancels a request that provably never reached a usable child.
    pub(super) fn cancel(&mut self, wire_id: &str) -> Option<PendingReply> {
        let pending = self.pending.remove(wire_id)?;
        self.finish(&pending.command_id);
        Some(pending)
    }

    pub(super) fn finish(&mut self, command_id: &CommandId) {
        self.in_flight
            .retain(|flight| &flight.command_id != command_id);
    }

    pub(super) fn finish_response(&mut self, command_id: &CommandId, command: &str, success: bool) {
        if !success || !TURN_COMMANDS.contains(&command) {
            self.finish(command_id);
        }
    }

    pub(super) fn associated(&self, wire_id: &str) -> Option<CommandId> {
        if let Some(pending) = self.pending.get(wire_id) {
            return Some(pending.command_id.clone());
        }
        self.in_flight
            .iter()
            .rev()
            .find(|flight| flight.command_id.as_str() == wire_id)
            .map(|flight| flight.command_id.clone())
    }

    pub(super) fn active_mutating(&self) -> Option<CommandId> {
        self.in_flight
            .iter()
            .rev()
            .find(|flight| flight.kind == InFlightKind::Mutating)
            .map(|flight| flight.command_id.clone())
    }

    /// Whether one command id anchors an in-flight TURN command of the
    /// current binding. The context-refusal authentication requires this:
    /// a refusal frame must attach to a live turn anchor, so a stale or
    /// unsolicited frame can never type a session terminal.
    pub(super) fn active_turn_anchor(&self, command_id: &CommandId) -> bool {
        self.in_flight.iter().any(|flight| {
            &flight.command_id == command_id && TURN_COMMANDS.contains(&flight.command.as_str())
        })
    }

    pub(super) fn settle_frame(&mut self, value: &Value) {
        match value.get("type").and_then(Value::as_str) {
            Some("prompt_result") => {
                if let Some(wire_id) = value.get("id").and_then(Value::as_str) {
                    if let Some(command_id) = self.associated(wire_id) {
                        self.finish(&command_id);
                    }
                }
            }
            Some("agent_end") if crate::live::rollover::terminal_agent_end(value) => {
                self.in_flight
                    .retain(|flight| !TURN_COMMANDS.contains(&flight.command.as_str()));
            }
            _ => {}
        }
    }

    pub(super) fn fail_all(&mut self, error: BridgeError) {
        let pending: Vec<PendingReply> = self.pending.drain().map(|(_, value)| value).collect();
        self.in_flight.clear();
        for entry in pending {
            let _ = entry.reply.send(Err(BridgeError::ProcessDown {
                detail: error.to_string(),
            }));
        }
    }
}

/// Commands whose effect must be resolved before new mutating work.
pub(super) const MUTATING_COMMANDS: [&str; 6] = [
    "prompt",
    "steer",
    "follow_up",
    "abort",
    "set_model",
    "checkpoint",
];
/// Commands that are re-executed verbatim by every (re)registration, so a
/// crash-leftover of these is reconciled as superseded, never replayed blind.
pub(super) const REGISTRATION_COMMANDS: [&str; 3] =
    ["get_state", "set_host_tools", "set_host_uri_schemes"];
/// Mutating commands whose effects can outlive their immediate RPC response
/// and remain the correlation anchor until a terminal turn frame arrives.
const TURN_COMMANDS: [&str; 4] = ["prompt", "steer", "follow_up", "abort"];

pub(super) enum PumpMessage {
    Send {
        generation: u64,
        frame: Value,
        ack: oneshot::Sender<Result<(), BridgeError>>,
    },
    SideResult {
        generation: u64,
        request_id: String,
        kind: SideChannelKind,
        result: Value,
        ack: oneshot::Sender<bool>,
    },
    Install {
        process: Box<OmpProcess>,
        ack: oneshot::Sender<Result<(), BridgeError>>,
    },
    Terminate {
        reason: String,
        /// True when the retirement is PLANNED (recovery/rollover respawn,
        /// probe crash injection): the child is replaced on purpose, so the
        /// teardown must never publish an unexpected-failure transition.
        /// False only for terminations that prove the incarnation died
        /// outside any planned lifecycle step.
        planned: bool,
        ack: oneshot::Sender<Result<Option<OmpExitRecord>, BridgeError>>,
    },
    Stop {
        /// Marks the durable row `Ended` after teardown when true; ordinary stop
        /// leaves it `ready` so a later daemon can reclaim the session.
        end_session: bool,
        ack: oneshot::Sender<Result<StopReport, BridgeError>>,
    },
}

/// Stamps the wire request id onto one outbound command frame; the journaled
/// body is then exactly the request the child receives.
pub(super) fn with_request_id(mut frame: Value, wire_id: &str) -> Value {
    let _ = frame
        .as_object_mut()
        .expect("command frame object literal")
        .insert("id".to_owned(), json!(wire_id));
    frame
}
