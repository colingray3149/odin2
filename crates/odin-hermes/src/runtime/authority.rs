//! Daemon-supplied conversation routes, authentication and approval delivery records.

use odin_domain::huginn::{LiveError, LiveSessionId};
use odin_domain::{ApprovalId, CapabilityId, EventId, ProjectId, SeatId};
use odin_ledger::Ledger;
use time::OffsetDateTime;

/// The exact declared ownership of one governed conversation, supplied by
/// the daemon from its published conversation declaration. There is no
/// inferred or default owner: a conversation surface composes only against
/// an explicit declaration whose seat and project match the configured
/// transport exactly and whose ask capability is an admitted contract that
/// delegates to precisely this seat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationOwnership {
    /// The declared conversation owner seat.
    pub seat: SeatId,
    /// The declared project the conversation runs in.
    pub project: ProjectId,
    /// The admitted capability contract that gates asks bound for this
    /// conversation; its declared `delegate_to` must equal [`Self::seat`].
    pub ask_capability: CapabilityId,
}

/// The live seat-authority facts intake governance consults on every
/// invocation, supplied by the daemon from its real operation authority —
/// current token/seat revocation and current stop state. No snapshot and
/// no ledger-only stand-in: the daemon binds the SAME authority it verifies
/// dispatch tokens against.
pub trait IntakeAuthorityFacts: Send + Sync {
    /// True when the seat's dispatch token is currently revoked.
    fn seat_token_revoked(&self, seat: &str) -> bool;
    /// True when the named durable intent identity is under a real
    /// current stop.
    fn stopped(&self, identity: &str) -> bool;
}

/// The typed reason one admitted or approved intent failed inside the
/// conversation route. This is the failure seam: the route names the
/// variant, the runtime renders the owner's one plain-language sentence
/// from it (never string-matching formatted errors), logs the detail, and
/// settles the durable task with it. Rendering lives in
/// [`crate::natural::natural_intent_failure`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IntentFailure {
    #[error("the conversation answer did not settle within its bound")]
    AnswerTimeout,
    /// The conversation vehicle's child exited and same-session recovery
    /// could not bring it back.
    #[error("the conversation vehicle was lost mid-answer and recovery failed")]
    VehicleLost,
    /// The vehicle recovery chain failed on the plane's typed refusal:
    /// the source is the original error, the session and observed epoch
    /// (never inferred) name the vehicle, and the daemon log carries the
    /// full chain while the owner's sentence stays generic.
    #[error(
        "conversation vehicle recovery failed at {step} for session {session} \
         (observed epoch {epoch:?}): {source}"
    )]
    VehicleRecoveryFailed {
        /// The exact vehicle session the recovery attempted.
        session: LiveSessionId,
        /// The epoch observed on the recovery path, when one was;
        /// `None` means none was observed, not an invented default.
        epoch: Option<u64>,
        /// Which step of the vehicle recovery chain failed.
        step: &'static str,
        /// The plane's typed refusal, preserved as the source.
        #[source]
        source: LiveError,
    },
    /// The conversation session refused the prompt because it is still
    /// settling.
    #[error("the conversation session is still settling and refused the prompt")]
    ConversationBusy,
    /// The session refused this turn's prompt before the model ran (its
    /// command completed failed): nothing was done, and waiting for an
    /// answer would only time out.
    #[error("the conversation turn was refused before it ran: {reason}")]
    TurnRefused { reason: String },
    /// The turn's request outgrew the model's declared context window (the
    /// authenticated `context_refusal.window_exceeded`): the conversation
    /// rolls to a successor and resends once; this is the honest failure
    /// when even the fresh successor cannot fit it.
    #[error("the conversation turn does not fit the model's context window")]
    ContextExhausted,
    /// The model's provider refused the turn (usage limit, rejected key,
    /// provider outage) and the turn settled without an answer: nothing was
    /// done, and waiting would only time out.
    #[error("the model provider refused the conversation turn: {reason}")]
    ModelUnavailable { reason: String },
    /// The turn settled without a reply to the owner, and one bounded
    /// reprompt on the same session settled without one too.
    #[error("the conversation turn ended without a reply, twice")]
    SilentTurn,
    /// The conversation history or listing could not be read.
    #[error("the conversation history could not be read")]
    HistoryUnavailable,
    /// Admitted-prompt provenance or the final reply could not be recorded or read.
    /// Keep the flight until its durable reply owns settlement, so the same
    /// key observes the original admission instead of submitting another prompt.
    #[error("the durable state of this conversation reply is unavailable")]
    ReplyStateUnavailable,
    /// The conversation vehicle is terminally closed and was not reopened.
    #[error("the conversation vehicle is closed and was not reopened")]
    ConversationClosed,
    /// Successive fresh conversation sessions ended before they served
    /// (their first open failed); the next is minted only after the
    /// durable backoff.
    #[error(
        "{attempts} conversation successor(s) ended before serving; the next is due at unix ms \
         {retry_at_unix_ms}"
    )]
    SuccessorStartBackoff {
        attempts: u32,
        retry_at_unix_ms: u64,
    },
    /// The durable cap of fresh sessions that ended before they served was
    /// reached under this daemon build: none is minted until a new build.
    #[error("{attempts} conversation successors ended before serving; no further one is minted")]
    SuccessorStartExhausted { attempts: u32 },
    /// Anything else: the detail is logged and settled durably, never
    /// rendered to the owner.
    #[error("{0}")]
    Other(String),
}

/// Opens a supervised worker for an existing kernel-accepted command;
/// ordinary Discord intents supply no parent session context.
#[async_trait::async_trait]
pub trait ApprovedIntentRoute: Send + Sync {
    /// Executes one approved intent exactly once. The returned JSON value
    /// is the settle projection of the real supervisor outcome; an `Err`
    /// is the typed refusal that settles the task durably failed — the
    /// owner's DM carries its rendered one-sentence notice, never the
    /// detail.
    async fn execute(
        &self,
        intent: ApprovedIntentExecution,
    ) -> Result<serde_json::Value, IntentFailure>;

    /// Executes intents that were waiting together, oldest first, one
    /// outcome each in the same order. A route that can answer them as
    /// one turn does.
    async fn execute_batch(
        &self,
        intents: Vec<ApprovedIntentExecution>,
    ) -> Vec<Result<serde_json::Value, IntentFailure>> {
        let mut outcomes = Vec::with_capacity(intents.len());
        for intent in intents {
            outcomes.push(self.execute(intent).await);
        }
        outcomes
    }
}

/// The one approved intent handed to a bound [`ApprovedIntentRoute`]: the
/// durable command identity, its idempotency key (the replay-safe
/// correlation), and the admitted intent text from the durable row.
#[derive(Clone, Debug)]
pub struct ApprovedIntentExecution {
    pub command_id: String,
    pub idempotency_key: String,
    pub content: String,
    /// Not the owner's input (a scheduled wake, an observed event): it runs
    /// as its own turn and is never folded into a running one.
    pub unprompted: bool,
}

/// The daemon-bound read-only terminal screen source serving the
/// `terminal.read` capability: one bounded capture of the operator's real
/// terminal session through the supervisor's resolved live target. The
/// runtime composes this seam unbound and every dispatch fails closed with
/// a typed unavailability until the daemon binds the real supervisor route.
pub trait TerminalReadRoute: Send + Sync {
    /// Reads the resolved governed terminal target's screen, bounded to
    /// `max_bytes`. `session` must name the resolved target.
    fn read_screen(&self, session: &str, max_bytes: usize) -> Result<TerminalScreenRead, String>;
}

/// One bounded terminal screen read as served to the capability handler.
#[derive(Clone, Debug)]
pub struct TerminalScreenRead {
    pub session: String,
    pub content: String,
    pub truncated: bool,
}

/// The daemon-bound read-only Huginn projection source serving the
/// `huginn.read` capability: the same status and session projections the
/// loopback daemon serves, read from the daemon's real plane. Unbound means
/// every dispatch fails closed with a typed unavailability.
pub trait HuginnReadRoute: Send + Sync {
    /// The daemon status projection.
    fn status(&self) -> Result<serde_json::Value, String>;
    /// The caller's own governed session projection.
    fn session_projection(&self, session: &str) -> Result<serde_json::Value, String>;
}

/// The kind of workspace surface one resolved connection opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceConnectionKind {
    /// A live zellij session, opened through the host's `zr` wrapper.
    Zellij,
    /// A declared project source tree, opened through `zed` over ssh.
    Zed,
}

impl WorkspaceConnectionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zellij => "zellij",
            Self::Zed => "zed",
        }
    }
}

/// One resolved workspace connection: the exact governed command the
/// operator's workspace surface opens, plus the declared host it reaches.
/// Every name is read from the daemon's declarations and live fleet
/// placements — never from model arguments beyond the target itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceConnection {
    pub command: String,
    pub kind: WorkspaceConnectionKind,
    pub host: String,
    pub target: String,
}

/// A dedicated desktop launch lease. Cleanup must match every cgroup identity field.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOwnership {
    pub unit: String,
    pub owner: WorkspaceCgroupOwner,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCgroupOwner {
    pub group: String,
    pub invocation: String,
    pub inode: u64,
    pub device: u64,
}

/// Resolves declared workspace targets read-only; separate methods open windows or type text.
/// Missing routes, unknown targets and offline hosts refuse rather than inventing a connection.
pub trait WorkspaceConnectRoute: Send + Sync {
    /// Resolves one connection. `host` optionally narrows to one declared
    /// fleet host by its tailscale name; `target` is a zellij session name
    /// or a declared project id.
    fn connect(&self, host: Option<&str>, target: &str) -> Result<WorkspaceConnection, String>;

    /// Opens the connection on the named device and returns a description of the window.
    /// Offline devices, missing graphical sessions and locked screens refuse without opening.
    fn open(&self, connection: &WorkspaceConnection, device: &str) -> Result<String, String> {
        let _ = (connection, device);
        Err("opening a workspace on a device is not bound on this daemon".to_owned())
    }

    /// Opens an isolated, run-owned window; never falls back to the shared desktop app.
    fn open_owned(
        &self,
        connection: &WorkspaceConnection,
        device: &str,
        launch_owner: &str,
    ) -> Result<(String, WorkspaceOwnership), String> {
        let _ = (connection, device, launch_owner);
        Err("owned workspace launch is not bound on this daemon".to_owned())
    }

    /// Types into the named device's focused window, optionally followed by Enter.
    /// Offline devices, missing graphical sessions and locked screens refuse without typing.
    fn input(&self, device: &str, text: &str, enter: bool) -> Result<(), String> {
        let _ = (device, text, enter);
        Err("typing on a device is not bound on this daemon".to_owned())
    }
}

/// A rendered authority-move step, never executed by the daemon.
/// `facts` supplies the revision/hash/audit checks for the operator's command.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FleetDrainPlanStep {
    pub step: u32,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<serde_json::Value>,
}

/// A declared standby candidate: an enabled, non-authoritative,
/// workload-allowing node whose host is online in the live fleet view.
/// Listing a candidate is not choosing it — the choice is explicitly the
/// operator's.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct StandbyCandidate {
    pub node: String,
    pub host: String,
}

/// The authority-move runbook: the ordered typed steps, the declared
/// standby candidates, and the note that says who decides. The plan is
/// data for the operator, never an execution.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AuthorityMovePlan {
    pub steps: Vec<FleetDrainPlanStep>,
    pub candidates: Vec<StandbyCandidate>,
    pub note: String,
}

/// The result of one governed fleet drain: either the pods were really
/// drained off the host's nodes, or the host holds the authority and the
/// answer is the move plan instead — the cluster is never touched.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FleetDrainResult {
    Drained,
    AuthorityMovePlan,
}

/// The typed outcome of one fleet drain, exactly the shape the
/// `fleet.drain` output schema declares. Pod-level honesty travels in
/// `evicted`/`remained`; a node that kept pods is a report, never an
/// error.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetDrainOutcome {
    pub host: String,
    pub node: String,
    pub result: FleetDrainResult,
    pub cordoned: bool,
    pub evicted: Vec<String>,
    pub remained: Vec<String>,
    pub authority_holds: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<AuthorityMovePlan>,
    /// What happened to each of the host's Odin pods (rehomed or paused).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<String>,
}

/// The typed outcome of one fleet restore: every node of the host was
/// uncordoned and the post-patch scheduler state is the real one read
/// back from the API server.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FleetRestoreOutcome {
    pub host: String,
    pub node: String,
    pub uncordoned: bool,
    pub schedulable: bool,
    /// The pods the drain paused, resumed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resumed: Vec<String>,
}

/// The read-only resolution both the preflight gate and the execution
/// re-run: the host's enabled registry nodes, which of them (if any)
/// holds the registry's authoritative state, and whether this daemon
/// composed a kube surface at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetDrainResolution {
    pub host: String,
    pub nodes: Vec<String>,
    pub authority_node: Option<String>,
    pub kube_ready: bool,
}

/// The daemon-bound fleet drain/restore surface serving the
/// `fleet.drain` and `fleet.restore` capabilities: one route, two model
/// tools. Resolution is declaration-and-read-model data only; the real
/// drain rides the daemon's kube cell under typed bounds; an authority
/// host is NEVER touched — the route returns the move plan and the real
/// transition stays operator-run. Unbound means every dispatch fails
/// closed with a typed unavailability.
pub trait FleetDrainRoute: Send + Sync {
    /// The complete read-only resolution: unknown host, offline host,
    /// node-less host, and a kube surface missing where one is required
    /// refuse typed here, before anything is journaled.
    fn resolve(&self, host: &str) -> Result<FleetDrainResolution, String>;
    /// Drains the host's nodes, or — when one of them holds the
    /// authority — returns the ordered move plan without touching the
    /// cluster.
    fn drain(&self, host: &str) -> Result<FleetDrainOutcome, String>;
    /// Uncordons every node of the host and reports the real post-patch
    /// scheduler state.
    fn restore(&self, host: &str) -> Result<FleetRestoreOutcome, String>;
}

/// One authenticated inbound owner message. The runtime constructs this
/// ONLY for a non-guild DM whose transport author matches the configured
/// paired owner — the authentication happens at this seam, so no decision
/// code ever sees a message that is not provably the owner's. The exact
/// declared seat and project bindings travel with the message; the
/// transport never guesses them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOwnerMessage {
    /// The paired owner's transport identity (Discord user snowflake).
    pub owner_user_id: String,
    /// The DM conversation the message arrived on (Discord channel
    /// snowflake) — the exact conversation a delivered question binds to.
    pub channel_id: String,
    /// The transport message identity (Discord message snowflake).
    pub message_id: String,
    /// The surface's declared seat binding.
    pub seat: SeatId,
    /// The surface's declared project binding.
    pub project: ProjectId,
    /// The whole message content, untrimmed of internal whitespace —
    /// interpretation is whole-message, never substring.
    pub content: String,
}

/// Interprets whole owner messages as decisions on delivered approval questions.
/// Returns `Some(ack)` when consumed, or `None` to leave the message as a normal intent.
#[async_trait::async_trait]
pub trait OwnerDecisionRoute: Send + Sync {
    async fn try_decision(
        &self,
        message: AuthenticatedOwnerMessage,
    ) -> Result<Option<String>, String>;
}

/// The audit kind under which every approval-question delivery proof is
/// recorded — in the SAME ledger as the approval row, so the evidence
/// travels with the authority record.
pub const APPROVAL_DELIVERY_AUDIT_KIND: &str = odin_ledger::approval::OWNER_PREVIEW_DELIVERY_KIND;

/// The durable proof that one plain-language approval question was
/// ACTUALLY delivered to one authenticated conversation. Every field is
/// exact: a decision is only ever valid for precisely this request at
/// precisely this revision, shown in precisely this conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDelivery {
    pub approval_id: ApprovalId,
    /// The kernel revision the owner was shown.
    pub revision: i64,
    pub capability_id: CapabilityId,
    /// The exact target session the gated request belongs to (the
    /// approval scope's target id, `run:live:<session>` for live
    /// vehicles).
    pub session: String,
    /// The surface binding proven at delivery: the live vehicle's durable
    /// seat/project AND the configured surface binding had to agree, so a
    /// channel later rebound to another seat/project cannot spend an old
    /// proof.
    pub seat: SeatId,
    pub project: ProjectId,
    pub channel_id: String,
    pub owner_user_id: String,
    /// The audit event the proof is recorded under; a settled decision's
    /// evidence reference names it.
    pub evidence_event_id: EventId,
    /// The transport identity of the final chunk of the complete question.
    pub sent_message_id: String,
    /// Captured when the send actually completed, never the pre-send clock.
    pub delivered_at: OffsetDateTime,
}

/// One delivered, still-decidable approval for one conversation, as the
/// decision route sees it: the exact request, the revision it was shown
/// at, and a short human label rendered from the declared contract
/// description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredApproval {
    pub approval_id: ApprovalId,
    pub revision: i64,
    pub capability_id: CapabilityId,
    pub session: String,
    pub label: String,
    /// The request detail the delivered question carried (recipient,
    /// subject, task) — a re-ask repeats it, never a bare label.
    pub detail: Option<String>,
}

/// Typed delivery failures. None is a success: a question that was not
/// provably sent records no evidence, so no decision can ever bind to it.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeliveryError {
    #[error("the discord surface is not configured")]
    NotConfigured,
    #[error("the question can only be delivered to the configured paired owner channel")]
    NotPaired,
    #[error("the approval {0} does not exist in this ledger")]
    NotFound(ApprovalId),
    #[error("the approval {0} has already moved past `requested`")]
    NotRequested(ApprovalId),
    #[error("the approval {0} has expired")]
    Expired(ApprovalId),
    #[error(
        "capability {0} is not an admitted contract with a usable declared \
             description; no question can be worded, none is invented"
    )]
    Undeclared(CapabilityId),
    #[error(
        "the requester session is not a live vehicle bound to this surface's \
             declared seat and project"
    )]
    TargetUnbound,
    #[error("the exact approval snapshot is unavailable: {0}")]
    SnapshotUnavailable(String),
    #[error("the approval question could not be delivered: {0}")]
    SendFailed(String),
    #[error("the delivery evidence could not be written: {0}")]
    Evidence(String),
}

/// The complete declaration of one draft attempt, present only when every
/// declared variable compiled. `declaration_digest` is the blake3 identity of
/// the exact canonical profile TOML bytes — the selector the publish step
/// re-proves, so the operator approves exactly this declaration and nothing
/// else.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadDeclaration {
    pub destination: String,
    pub declaration_digest: String,
    pub rendered_toml: String,
}

/// One draft result: the clarification list when incomplete, the full
/// declaration when complete, plus the declared lane-availability and seat
/// facts the conversation reports honestly.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadDraft {
    pub profile_id: String,
    /// Registry revision the draft was compiled against (provenance).
    pub base_revision: u64,
    /// Exact NEW registry revision the publication installs: base + 1.
    /// The model passes this verbatim as workload.publish's
    /// expectedRegistryRevision.
    pub publish_revision: u64,
    pub declaration: Option<WorkloadDeclaration>,
    pub missing: Vec<WorkloadClarification>,
    pub lane: Option<WorkloadLaneAvailability>,
    pub seat_limits: Option<WorkloadSeatLimits>,
    /// Once the seat and project are answered: the memory namespaces that
    /// pair admits (the project declares them and the seat's brain scope
    /// holds them) — the only lawful memoryNamespace answers.
    #[serde(default)]
    pub memory_namespaces: Option<Vec<String>>,
}
/// Typed decision refusals on the delivered-approval surface. Every
/// variant refuses BEFORE anything is authorized; nothing here records a
/// decision.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DecisionRefusal {
    #[error("the message is not this surface's paired owner conversation")]
    NotAuthenticated,
    #[error(
        "no question for approval {0} was actually delivered to this conversation; \
             nothing is authorized"
    )]
    Undelivered(ApprovalId),
    #[error("the delivered revision {shown} does not match the claimed revision {claimed}")]
    Superseded { shown: i64, claimed: i64 },
    #[error("the approval {0} is no longer open")]
    NotOpen(ApprovalId),
    #[error("the approval {0} has expired")]
    Expired(ApprovalId),
    #[error("the request's conversation session is retired; the approval is stale")]
    SessionRetired,
    #[error("this reply does not provably follow the delivered question; nothing is authorized")]
    PredatesDelivery(ApprovalId),
    #[error("this reply already settled its approval; nothing new is authorized")]
    IntakeConsumed(ApprovalId),
    #[error("the delivery evidence could not be read: {0}")]
    Evidence(String),
    #[error("the decision did not settle: {0}")]
    Ledger(String),
}

/// The stored form of one delivery proof inside its audit payload.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApprovalDeliveryPayload {
    pub(super) approval_id: String,
    pub(super) revision: i64,
    pub(super) capability_id: String,
    pub(super) session: String,
    pub(super) seat: String,
    pub(super) project: String,
    pub(super) channel_id: String,
    pub(super) owner_user_id: String,
    pub(super) evidence_event_id: String,
    /// The transport's identity for the final chunk of the complete question —
    /// the causal anchor every decision orders the reply against.
    pub(super) sent_message_id: String,
    /// Old clipped questions cannot witness exact-content consent.
    #[serde(default)]
    pub(super) complete_snapshot: bool,
    /// The conversation vehicle (`run:live:<session>`) a delegated worker's
    /// question was delivered through; absent for the vehicle's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) via: Option<String>,
}

/// Renders the journaled request selected by [`durable_retry_arguments`].
pub(super) fn durable_question_detail(
    ledger: &Ledger,
    approval: &odin_ledger::approval::Approval,
) -> Option<String> {
    let (arguments, _) = durable_retry_arguments(ledger, approval)?;
    crate::natural::detail_from_request_json(&arguments)
}

/// Matches journaled and retry arguments by issuer, capability and digest, not
/// target id, so approvals transferred to a successor still find the original call.
pub(crate) fn durable_retry_arguments(
    ledger: &Ledger,
    approval: &odin_ledger::approval::Approval,
) -> Option<(String, serde_json::Value)> {
    let mut statement = ledger
        .connection()
        .prepare(
            "SELECT arguments_json FROM commands \
             WHERE issuer = ?1 AND target_kind = ?2 AND capability_id = ?3 \
             ORDER BY issued_at DESC LIMIT 64",
        )
        .map_err(|error| tracing::error!(error = %error, "odin-hermes: approval call lookup failed: {error}"))
        .ok()?;
    let rows = statement
        .query_map(
            [
                approval.issuer.as_str(),
                approval.scope.target_kind.as_str(),
                approval.scope.capability_id.as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .ok()?;
    for row in rows {
        let Ok(arguments) = row else { continue };
        let Ok(mut retry) = serde_json::from_str::<serde_json::Value>(&arguments) else {
            continue;
        };
        let Some(retry_object) = retry.as_object_mut() else {
            continue;
        };
        retry_object.insert(
            "approvalId".to_owned(),
            serde_json::Value::String(approval.approval_id.to_string()),
        );
        if odin_kernel::arguments_digest(&retry) == approval.scope.arguments_digest {
            return Some((arguments, retry));
        }
    }
    None
}

/// Reads up to 256 delivery records newest-first, filtering owner/channel before
/// the limit so other conversations cannot displace them; incomplete rows are skipped.
pub(super) fn latest_deliveries(
    ledger: &Ledger,
    channel_id: &str,
    owner_user_id: &str,
    declares_preview: impl Fn(&str) -> bool,
) -> Result<Vec<(ApprovalDeliveryPayload, OffsetDateTime)>, DecisionRefusal> {
    const RECENT: i64 = 256;
    let mut statement = ledger
        .connection()
        .prepare(
            "SELECT payload_json, occurred_at FROM audit_events \
             WHERE kind = ?1 \
               AND json_extract(payload_json, '$.channelId') = ?2 \
               AND json_extract(payload_json, '$.ownerUserId') = ?3 \
             ORDER BY sequence DESC LIMIT ?4",
        )
        .map_err(|error| DecisionRefusal::Evidence(error.to_string()))?;
    let rows = statement
        .query_map(
            rusqlite::params![
                APPROVAL_DELIVERY_AUDIT_KIND,
                channel_id,
                owner_user_id,
                RECENT
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| DecisionRefusal::Evidence(error.to_string()))?;
    let mut deliveries = Vec::new();
    for row in rows {
        let (payload_json, occurred_at) =
            row.map_err(|error| DecisionRefusal::Evidence(error.to_string()))?;
        let Ok(payload) = serde_json::from_str::<ApprovalDeliveryPayload>(&payload_json) else {
            continue;
        };
        if declares_preview(&payload.capability_id) && !payload.complete_snapshot {
            continue;
        }
        let occurred_at = odin_ledger::decode_utc(&occurred_at)
            .map_err(|error| DecisionRefusal::Evidence(error.to_string()))?;
        deliveries.push((payload, occurred_at));
    }
    Ok(deliveries)
}
/// One declared skeleton variable the draft still needs: the exact variable
/// name and the skeleton contract's own declared meaning. The model asks the
/// short question in its declared conversation style; the wording is never
/// compiled here.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadClarification {
    pub variable: String,
    pub meaning: String,
}

/// Declared model availability facts for the draft's gateway lane, read from
/// the deployment's real provider status at draft time. `available: false`
/// means the lane holds no active provider lease right now; the declared
/// alternatives are the other enabled lanes that do. Nothing swaps: the
/// fallback stays an offer the operator approves through the existing
/// declared change path.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadLaneAvailability {
    pub lane: String,
    pub available: bool,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub declared_alternatives: Vec<String>,
}

/// The bound seat's declared count constraints: how many live sessions and
/// parallel runs the seat's own declaration allows the pod to join. Declared
/// data, never an invented default.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSeatLimits {
    pub seat: String,
    pub max_sessions: u16,
    pub max_parallel_runs: u16,
}

/// Collected draft answers; missing required answers become clarifications.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WorkloadDraftAnswers {
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub seat: Option<String>,
    pub project: Option<String>,
    pub gateway_lane: Option<String>,
    pub allow_hosts: Option<Vec<String>>,
    pub screen: Option<String>,
    pub stream: Option<bool>,
    pub state_path: Option<String>,
    pub state_storage: Option<String>,
    pub export_pod_path: Option<String>,
    pub export_host_folder: Option<String>,
    pub brief_text: Option<String>,
    pub memory_namespace: Option<String>,
    pub deadline_seconds: Option<u64>,
    /// `script` (no agent) or `omp`; absent: an agent pod.
    pub harness: Option<String>,
    /// A script pod's own digest-pinned image (an agent pod runs the
    /// platform's image, a deployment fact).
    pub image_reference: Option<String>,
    pub script_command: Option<Vec<String>>,
    pub gpu_count: Option<u64>,
    pub placement: Option<Vec<String>>,
    /// `job` or `service`.
    pub mode: Option<String>,
    pub monitoring_cadence_seconds: Option<u64>,
    /// Watchdog tables, verbatim (the skeleton compiler owns their grammar).
    pub watchdogs: Option<Vec<serde_json::Value>>,
    /// Anti-stuck: the progress counter, stall window and recovery ladder.
    pub progress: Option<String>,
    pub stall_seconds: Option<u64>,
    pub recovery: Option<serde_json::Value>,
    /// Host capabilities the pod's agent may call.
    pub tools: Option<Vec<String>>,
}

/// One conversational draft request: the new profile's registry id, the
/// answers collected so far, and — when the caller holds a draft context —
/// the registry revision that context was validated against.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WorkloadDraftRequest {
    pub profile_id: String,
    pub answers: WorkloadDraftAnswers,
    pub expected_registry_revision: Option<u64>,
}

/// One publish request: the profile id the draft belongs to, the digest
/// of the draft `workload_draft` retained in the durable compiled-draft
/// store under exactly that (profile id, digest, revision) key, plus the
/// exact NEW registry revision the publication installs. No answers
/// travel: the route loads the retained declaration by this identity —
/// re-deriving it from model-supplied values would let a silent redraft
/// convert one approval into a different publication, and a request
/// naming another profile can never load this draft. An unknown identity
/// refuses typed before anything touches the worktree or the approval
/// gate.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkloadPublishRequest {
    pub profile_id: String,
    pub declaration_digest: String,
    pub expected_registry_revision: u64,
}

/// One successful publication through the existing committed-worktree chain:
/// the published revision, the commit the snapshot was derived from, and the
/// daemon's pinned revision at publish time — so the caller can honestly
/// report that the new profile is not dispatchable until the daemon re-pins.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadPublication {
    pub profile_id: String,
    pub destination: String,
    pub declaration_digest: String,
    pub published_revision: u64,
    pub pinned_revision: u64,
    pub commit: String,
    pub outcome: String,
}

/// Every typed authoring failure. None fabricates a state: stale revisions
/// and digest mismatches invalidate the old scope, and the caller re-drafts
/// rather than retries blindly.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkloadAuthoringFailure {
    /// The skeleton/relational compiler rejected the declaration values.
    #[error("the draft declaration is invalid: {issues:?}")]
    InvalidDeclaration { issues: Vec<String> },
    /// The compiled declaration is not the approved one: the old approval
    /// scope is invalidated, a fresh draft + approval is required.
    #[error("declaration digest mismatch: approved {approved}, compiled {compiled}")]
    DigestMismatch { approved: String, compiled: String },
    /// The registry advanced past the revision the draft context bound: the
    /// stale scope is dead, never retried.
    #[error("stale draft scope: bound revision {bound}, next registry revision is {next}")]
    StaleRevision { bound: u64, next: u64 },
    /// The authoring worktree is not a clean linked Git worktree at a
    /// committed HEAD, so the existing publication chain cannot run.
    #[error("authoring worktree is unusable: {reason}")]
    WorktreeInvalid { reason: String },
    /// The store refused the publication (active-revision check, invalid
    /// candidate, IO). The operation identity is preserved: nothing
    /// published, nothing half-applied.
    #[error("registry publication refused: {reason}")]
    PublicationRefused { reason: String },
    /// The durable draft store refused (IO or serialization): nothing was
    /// published and nothing is fabricated; the failure is typed.
    #[error("workload draft retention failed: {reason}")]
    DraftRetention { reason: String },
    /// The dedicated bridge thread did not return within its bound; the
    /// operation identity stays with the journaled command, never guessed.
    #[error("{operation} did not complete within its bound")]
    BridgeTimeout { operation: &'static str },
    /// The publish referenced a declaration digest with no retained draft
    /// (or none at that bound revision): the approval scope is dead, a
    /// fresh draft + approval is required.
    #[error("no draft {digest} is retained at bound revision {bound_registry_revision}")]
    UnknownDraft {
        digest: String,
        bound_registry_revision: u64,
    },
}

/// The daemon-bound conversational workload authoring route. Sync like the
/// other daemon seams; the implementation bridges its blocking work off the
/// async composition runtime on its own.
pub trait WorkloadAuthoringRoute: Send + Sync {
    /// Compiles one skeleton-derived draft and returns its declared
    /// clarifications or its complete declaration.
    fn draft(
        &self,
        request: WorkloadDraftRequest,
    ) -> Result<WorkloadDraft, WorkloadAuthoringFailure>;

    /// Reproves the exact approved declaration and publishes it through
    /// the existing committed-worktree chain. The kernel dispatch gate has
    /// already consumed the operator's approval for THIS exact argument set
    /// before this runs; this method never consumes anything again.
    fn publish(
        &self,
        request: WorkloadPublishRequest,
    ) -> Result<WorkloadPublication, WorkloadAuthoringFailure>;

    /// Read-only publish preparation, observed BEFORE the dispatch gate
    /// mints or consumes the operator's approval: retained-draft
    /// identity/integrity, current revision scope (including exact-replay
    /// eligibility proven against the durable receipt), the worktree
    /// prerequisites, and the pure candidate validation. Effect-free by
    /// contract — no staging, commit, retained-record write, authoring
    /// lock, publication, or snapshot adoption; every proof reuses the
    /// execution's own helpers. Execution re-proves under the lock.
    fn prepare_publish(
        &self,
        request: &WorkloadPublishRequest,
    ) -> Result<(), WorkloadAuthoringFailure>;

    /// Checks registry revision agreement before journaling, without effects as in [`Self::prepare_publish`].
    fn prepare_draft(&self, request: &WorkloadDraftRequest)
        -> Result<(), WorkloadAuthoringFailure>;
}
