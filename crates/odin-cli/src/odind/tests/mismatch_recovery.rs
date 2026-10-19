//! Generation rollover across daemon restarts preserves conversation history
//! without replaying settled effects or changing the predecessor's token.
//! Only the harness backend is replaced by a loopback transport.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use odin_domain::huginn::ApprovalDecision;
use odin_domain::huginn::{
    CommandOutcome, LiveCommand, LiveCommandBody, LiveContentBlock, LiveError, LiveEventBody,
    LiveMessage, LiveSessionId, LiveSessionState, ModelName, ProviderName, SessionEpoch,
    SessionManifest,
};
use odin_domain::{ApprovalId, CommandId, Digest, NodeId};
use odin_hermes::conversation::ConversationAuthority as _;
use odin_hermes::correlation::{identity_from_key, surface_correlation, DiscordSurface};
use odin_hermes::ingress::{INTENT_COMMAND_PREFIX, INTENT_ISSUER};
use odin_hermes::runtime::{ApprovedIntentExecution, ApprovedIntentRoute as _};
use odin_kernel::StopAuthority;
use odin_ledger::command::{
    CommandOutcome as LedgerCommandOutcome, CommandSpec, CommandTerminalStatus, RecordCommand,
};
use odin_omp::host_tools::delegation::DelegationLinkLedger;
use odin_omp::host_tools::operations::{
    wall_clock, ProvisionedFreshAuthorityProvider, SessionOperationBinding, StaticSchemaCatalog,
};
use odin_omp::live::control::LiveControlBackend;
use odin_omp::live::lane_artifacts::{FsLaneArtifactPort, LaneTransferBridge};
use odin_omp::live::ledger::fs::FsLiveLedger;
use odin_omp::live::ledger::{LiveLedger, NewLiveEvent};
use odin_omp::live::runtime::SessionCapsuleAuthority;
use odin_omp::live::runtime::{ProductionBridgeRuntimeConfig, ProductionBridgeRuntimeFactory};
use odin_omp::live::service::OmpLiveService;
use odin_omp::live::supervisor::{
    session_id_for, BridgeRuntimeFactory, LiveSessionLauncher, LiveSupervisor, SessionRuntime,
};
use odin_omp::live::transfer::{RegistryTransferLaneResolver, TransferManager};
use odin_omp::probe::PINNED_OMP_SOURCE_REVISION;
use odin_omp::process::{OmpProcessSpec, OmpWorkerLaunch};
use odin_process::{BusAddress, RegisteredServiceBinding, ScopeLimits, WorkerChannel};
use odin_registry::{SnapshotStore, ValidatedSnapshotCandidate};
use odin_types::CorrelationId;

use crate::authority::DeclaredConversationAuthority;
use crate::live::hermes_routes::tests::{gate_fixture_with, GateFixture};
use crate::test_support::commit_all;

/// Distinguishes a user DM reply from startup and rollover prompts.
pub(crate) const DM_PAYLOAD: &str = "DM-PAYLOAD-7F3A: what changed in the registry today?";
pub(crate) const DM_REPLY: &str = "REPLY:7F3A acknowledged — the registry gained revision 2 today.";
/// The staged pre-rollover accepted prompt: its settled effect must never
/// replay onto the fresh session.
const PRE_DM_TEXT: &str = "PRE-ACCEPTED-DM: earlier owner request already settled.";
/// The harness answer for every non-DM prompt (open/brief prompts).
pub(crate) const OPEN_ACK: &str = "harness open acknowledged";
/// The staged admitted-unsettled prompt: really admitted into the command
/// journal, its provider answer already durable, and the root crashed
/// before it could settle the intent.
const IN_FLIGHT_TEXT: &str = "IN-FLIGHT-DM-9C21: owner request admitted before the crash.";
/// The journaled provider answer for the admitted-unsettled prompt: the
/// durable fact the next intent observes instead of resending anything.
const IN_FLIGHT_ANSWER: &str = "REPLY:9C21 acknowledged — answered before the rollover.";
/// The Discord surface identity of the staged history turn: the intake
/// path derives its durable command id and idempotency key from it.
const PRE_HISTORY_MESSAGE_ID: &str = "9000000000000000001";
const OLDER_VEHICLE_MESSAGE_ID_ONE: &str = "9000000000000000002";
const OLDER_VEHICLE_MESSAGE_ID_TWO: &str = "9000000000000000003";

/// The deterministic predecessor vehicle identity.
fn vehicle_command() -> CommandId {
    CommandId::new("command:conversation-open:mismatch-recovery-fixture").expect("vehicle command")
}

fn predecessor_session() -> LiveSessionId {
    session_id_for(&vehicle_command()).expect("deterministic predecessor session")
}

fn message_text(message: &LiveMessage) -> String {
    message
        .content
        .iter()
        .map(|block| match block {
            LiveContentBlock::Text(text) => text.clone(),
            _ => String::new(),
        })
        .collect()
}

/// The deterministic harness answer: DM payloads get the message-specific
/// reply, everything else the distinct open ack.
fn answer_text(prompt: &str) -> String {
    if !prompt.starts_with(odin_omp::live::rollover::ROLLOVER_PROMPT_MARKER)
        && prompt.contains(DM_PAYLOAD)
    {
        DM_REPLY.to_owned()
    } else {
        OPEN_ACK.to_owned()
    }
}

/// Shared observations: every launcher open and every prompt the harness
/// backend received, for the replay, brief, and answer assertions.
#[derive(Default)]
pub(crate) struct LaunchProbe {
    pub(crate) opens: Mutex<Vec<OpenRecord>>,
    pub(crate) prompts: Mutex<Vec<String>>,
    pub(crate) delivered: Mutex<Vec<odin_hermes::egress::OutboundMessage>>,
    reject_prompt: AtomicBool,
    fail_prompt_transport: AtomicBool,
}

#[async_trait]
impl odin_hermes::egress::OutgoingSink for LaunchProbe {
    async fn deliver(
        &self,
        message: odin_hermes::egress::OutboundMessage,
        checkpoint: Arc<dyn odin_hermes::egress::DeliveryCheckpoint>,
    ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
        use odin_hermes::egress::{DeliveryOperation, EgressError, OutboundMessage, ReplyChunks};
        let plan = checkpoint.prepare(&message)?;
        let mut held: Vec<_> = plan
            .ownership
            .as_ref()
            .map(|owned| owned.refs().cloned().collect())
            .unwrap_or_default();
        for operation in &plan.operations {
            let reservation = checkpoint.reserve(operation)?;
            let result = match operation {
                DeliveryOperation::Post { content, .. } => self
                    .send(OutboundMessage {
                        channel_id: message.channel_id.clone(),
                        content: content.clone(),
                    })
                    .await
                    .map(|reply| Some(reply.anchor)),
                DeliveryOperation::Patch {
                    reference, content, ..
                } => self
                    .edit(
                        &ReplyChunks::single(reference.clone()),
                        OutboundMessage {
                            channel_id: message.channel_id.clone(),
                            content: content.clone(),
                        },
                    )
                    .await
                    .map(|reply| Some(reply.anchor)),
                DeliveryOperation::Delete { reference } => {
                    let mut delivered = self.delivered.lock().expect("delivery log");
                    let slot = reference
                        .message_id
                        .strip_prefix("fixture-message-")
                        .and_then(|index| index.parse::<usize>().ok())
                        .and_then(|index| delivered.get_mut(index));
                    match slot {
                        Some(slot) => {
                            slot.content.clear();
                            Ok(None)
                        }
                        None => Err(EgressError::InvalidState("no such delivered message")),
                    }
                }
            };
            let reference = match result {
                Ok(reference) => reference,
                Err(error) => {
                    if let EgressError::Transport(source) = &error {
                        checkpoint.failed(&reservation, source)?;
                    }
                    return Err(error);
                }
            };
            checkpoint.acknowledge(&reservation, reference.as_ref())?;
            match operation {
                DeliveryOperation::Post { .. } => held.push(reference.expect("POST reference")),
                DeliveryOperation::Patch { index, .. } => {
                    held[*index] = reference.expect("PATCH reference")
                }
                DeliveryOperation::Delete { reference } => held.retain(|held| held != reference),
            }
        }
        checkpoint.complete()?;
        let mut held = held.into_iter();
        Ok(ReplyChunks {
            anchor: held
                .next()
                .ok_or(EgressError::InvalidState("no acknowledged messages"))?,
            tails: held.collect(),
        })
    }

    async fn send(
        &self,
        message: odin_hermes::egress::OutboundMessage,
    ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
        let mut delivered = self.delivered.lock().expect("delivery log");
        let receipt = odin_hermes::discord::DiscordMessageRef {
            channel_id: message.channel_id.clone(),
            message_id: format!("fixture-message-{}", delivered.len()),
        };
        delivered.push(message);
        Ok(odin_hermes::egress::ReplyChunks::single(receipt))
    }

    async fn edit(
        &self,
        current: &odin_hermes::egress::ReplyChunks,
        message: odin_hermes::egress::OutboundMessage,
    ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
        let mut delivered = self.delivered.lock().expect("delivery log");
        let slot = current
            .anchor
            .message_id
            .strip_prefix("fixture-message-")
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| delivered.get_mut(index))
            .ok_or(odin_hermes::egress::EgressError::InvalidState(
                "no such delivered message",
            ))?;
        *slot = message;
        Ok(current.clone())
    }

    async fn typing(&self, _channel_id: &str) -> Result<(), odin_hermes::egress::EgressError> {
        Ok(())
    }
}

/// One launcher open observation: the supervisor's durable identity, the
/// epoch it launched at, and whether the open was a reclaim.
#[derive(Clone, Debug)]
pub(crate) struct OpenRecord {
    pub(crate) session: LiveSessionId,
    pub(crate) epoch: u64,
    pub(crate) reclaim: bool,
}

impl LaunchProbe {
    fn record_open(&self, session: LiveSessionId, epoch: SessionEpoch, reclaim: bool) {
        self.opens.lock().expect("open log").push(OpenRecord {
            session,
            epoch: epoch.get(),
            reclaim,
        });
    }

    pub(crate) fn opens(&self) -> Vec<OpenRecord> {
        self.opens.lock().expect("open log").clone()
    }

    /// Records one harness prompt and returns its EMISSION index: the
    /// unique, monotonic identity of this exact prompt in the log.
    fn record_prompt(&self, prompt: String) -> usize {
        let mut prompts = self.prompts.lock().expect("prompt log");
        prompts.push(prompt);
        prompts.len() - 1
    }

    pub(crate) fn prompt_count(&self, needle: &str) -> usize {
        self.prompts
            .lock()
            .expect("prompt log")
            .iter()
            .filter(|prompt| prompt.contains(needle))
            .count()
    }

    pub(crate) fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompt log").clone()
    }
}

/// The harness backend: the loopback provider transport. Every prompt is
/// recorded and answered into the session journal — the REAL ledger the
/// conversation answer wait drains.
struct HarnessBackend {
    observations: tokio::sync::broadcast::Sender<odin_omp::bridge::ObservedFrame>,
    probe: Arc<LaunchProbe>,
}

#[async_trait]
impl LiveControlBackend for HarnessBackend {
    async fn prompt(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let text = message_text(message);
        self.probe.record_prompt(text.clone());
        if self.probe.reject_prompt.swap(false, Ordering::SeqCst) {
            // A negative backend response proves this dispatch failed. A
            // transport loss instead leaves admission's outcome unresolved.
            return Err(LiveError::InvalidRequest {
                code: "fixture_prompt_rejected".to_owned(),
                message: "the harness rejected this prompt before execution".to_owned(),
            });
        }
        if self
            .probe
            .fail_prompt_transport
            .swap(false, Ordering::SeqCst)
        {
            return Err(LiveError::Unavailable {
                code: "fixture_prompt_transport_failed".to_owned(),
            });
        }
        let observations = self.observations.clone();
        tokio::spawn(async move {
            // Model transport completes after prompt admission, not inside it.
            tokio::time::sleep(StdDuration::from_millis(25)).await;
            for frame in [
                serde_json::json!({"type": "agent_start"}),
                serde_json::json!({
                    "type": "message_end",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": answer_text(&text)}],
                    },
                }),
                serde_json::json!({"type": "agent_end"}),
            ] {
                let raw = format!("{frame}\n");
                let decoded = odin_omp::frames::RpcFrameDecoder::default()
                    .push_physical_line(raw.as_bytes())
                    .expect("scripted frame decodes")
                    .expect("complete frame");
                observations
                    .send(odin_omp::bridge::ObservedFrame {
                        class: odin_omp::bridge::classify_frame(decoded.value()),
                        decoded: Some(decoded),
                        rejection: None,
                        active_command: None,
                        journal_failure: None,
                    })
                    .expect("the admitted turn retains its observation receiver");
            }
        });
        Ok(())
    }

    async fn follow_up(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }

    async fn steer(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }

    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn checkpoint(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn restart(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn rehome(&self, _target_node: &odin_domain::NodeId) -> Result<(), LiveError> {
        Ok(())
    }

    async fn set_model(
        &self,
        _provider: &ProviderName,
        _model: &ModelName,
    ) -> Result<(), LiveError> {
        Ok(())
    }

    async fn abort_turn(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn abort_session(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn decide_permission(
        &self,
        _request_id: &odin_domain::huginn::PermissionRequestId,
        _decision: odin_domain::huginn::PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }

    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }

    async fn bridge_ready(&self) -> bool {
        true
    }
}

/// The seat capsule authority the factory composes: the fixture accepts
/// every capsule open, exactly like the bridge-launch fixture.
struct AcceptingCapsules;

impl SessionCapsuleAuthority for AcceptingCapsules {
    fn open_session(
        &self,
        _session: &odin_domain::SessionId,
        _binding: &SessionOperationBinding,
        _capsule_root: &Path,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

/// Use the production factory with loopback transport; injected open failures leave no durable launch.
pub(crate) struct BoundaryLauncher {
    /// Armed after the fixture composes (the factory needs the fixture
    /// config); the supervisor never launches before that.
    factory: OnceLock<Arc<ProductionBridgeRuntimeFactory>>,
    probe: Arc<LaunchProbe>,
    fail_next_open: AtomicBool,
}

impl BoundaryLauncher {
    pub(crate) fn new(probe: Arc<LaunchProbe>) -> Self {
        Self {
            factory: OnceLock::new(),
            probe,
            fail_next_open: AtomicBool::new(false),
        }
    }

    pub(crate) fn arm(&self, factory: Arc<ProductionBridgeRuntimeFactory>) {
        let _ = self.factory.set(factory);
    }

    /// Arms the ONE crash analogue: the next launch refuses before any
    /// effect, exactly like a daemon death between the predecessor close
    /// and the successor open.
    fn fail_next_open(&self) {
        self.fail_next_open.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl LiveSessionLauncher for BoundaryLauncher {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        if self.fail_next_open.swap(false, Ordering::SeqCst) {
            return Err(LiveError::Unavailable {
                code: "rollover_crash_analogue".to_owned(),
            });
        }
        let factory = self
            .factory
            .get()
            .expect("the regression arms the factory before any launch");
        // The REAL production composition site: declaration projection,
        // retained-publication material, provisioned-token resolve.
        factory.build(manifest, reclaim).await?;
        self.probe.record_open(manifest.session_id, epoch, reclaim);
        let (observations, receiver) = tokio::sync::broadcast::channel(16);
        Ok(SessionRuntime {
            control: Arc::new(HarnessBackend {
                observations,
                probe: self.probe.clone(),
            }),
            terminal: None,
            observations: Some(receiver),
            failed_notices: None,
        })
    }
}

/// One staged generation row over the shared route-gate fixture.
pub(crate) struct GenerationFixture {
    pub(crate) gate: GateFixture,
    pub(crate) probe: Arc<LaunchProbe>,
    pub(crate) launcher: Arc<BoundaryLauncher>,
    pub(crate) root: Arc<odin_hermes::conversation::ConversationRoot>,
    pub(crate) ledger: Arc<dyn LiveLedger>,
    pub(crate) capsules: Arc<dyn SessionCapsuleAuthority>,
    pub(crate) authority: DeclaredConversationAuthority,
    pub(crate) vehicle_command: CommandId,
    pub(crate) session: LiveSessionId,
    pub(crate) token_file: PathBuf,
    pub(crate) record_path: PathBuf,
}

impl GenerationFixture {
    /// Rebuilds the REAL serving stack over the SAME durable state: a
    /// fresh file-backed ledger (its open replays the change journal —
    /// the daemon-restart analogue), a fresh supervisor, a fresh plane,
    /// and a fresh conversation root composed from the SAME retained
    /// record.
    pub(crate) async fn reopen(&mut self) {
        let live: Arc<dyn LiveLedger> = Arc::new(
            FsLiveLedger::open(self.gate._root.path().join("live-ledger"))
                .expect("reopen the live ledger"),
        );
        let probe = Arc::new(LaunchProbe::default());
        self.gate
            .runtime
            .bind_notify_sink(probe.clone())
            .expect("reopened isolated egress");
        let launcher = Arc::new(BoundaryLauncher::new(probe.clone()));
        let serving = compose_serving_with(
            &self.gate,
            launcher.clone(),
            live.clone(),
            self.capsules.clone(),
        )
        .await;
        self.probe = probe;
        self.launcher = launcher;
        self.root = serving.root;
        self.ledger = live;
    }
}

async fn is_terminal(fixture: &GenerationFixture, session: LiveSessionId) -> bool {
    LiveSupervisor::new(fixture.ledger.clone(), fixture.launcher.clone(), 8, None)
        .terminal_summary(session)
        .await
        .expect("canonical terminal projection")
        .is_some()
}

/// Publishes `revision` over the fixture worktree: a description bump is
/// the smallest lawful registry change, committed and published through
/// the production `publish_committed` path so the retained-publication
/// material source can recompose every revision.
/// The CURRENT description line is rewritten, whatever revision it names:
/// an original-only match would leave revision 3 unable to replace
/// revision 2's already-bumped line.
fn publish_revision(gate: &GateFixture, worktree: &Path, revision: u64) {
    let seat_toml = worktree.join("registry/seats/coordinator/seat.toml");
    let body = std::fs::read_to_string(&seat_toml).expect("fixture seat toml");
    // Rewrite the CURRENT description line, whatever revision it names.
    const DESCRIPTION_LINE: &str = "description = \"route gate fixture coordinator seat";
    let mut updated = body
        .lines()
        .map(|line| {
            if line.starts_with(DESCRIPTION_LINE) {
                format!("{DESCRIPTION_LINE} r{revision}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if body.ends_with('\n') {
        updated.push('\n');
    }
    assert_ne!(
        body, updated,
        "the fixture seat toml exposes its description"
    );
    std::fs::write(&seat_toml, updated).expect("bump seat description");
    let commit = commit_all(worktree, &format!("rollover fixture revision {revision}"));
    let snapshot_path = gate._root.path().join("state/registry/snapshot.json");
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("committed rollover fixture candidate");
    SnapshotStore::new(&snapshot_path)
        .publish_committed(&candidate, revision)
        .expect("publish rollover fixture snapshot");
}

/// Commits the worktree as it stands and publishes it as `revision`.
fn publish_worktree(gate: &GateFixture, worktree: &Path, revision: u64) {
    let commit = commit_all(worktree, &format!("fixture revision {revision}"));
    let snapshot_path = gate._root.path().join("state/registry/snapshot.json");
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("committed fixture candidate");
    SnapshotStore::new(&snapshot_path)
        .publish_committed(&candidate, revision)
        .expect("publish fixture snapshot");
}

/// Mints the installed token through the REAL declared authority at the
/// CURRENT pin, returning the ensured bound and current generations.
pub(crate) async fn mint_installed_token(
    authority: &DeclaredConversationAuthority,
    vehicle_command: &CommandId,
    session: &LiveSessionId,
) -> odin_hermes::conversation::EnsuredGeneration {
    authority
        .ensure(vehicle_command, *session)
        .await
        .expect("the real authority mints the installed token")
}

/// The ensured report the REAL authority holds for one (command, session)
/// pair right now: the token's frozen bound and the live pinned current.
async fn ensured(
    fixture: &GenerationFixture,
    vehicle_command: &CommandId,
    session: &LiveSessionId,
) -> odin_hermes::conversation::EnsuredGeneration {
    fixture
        .authority
        .ensure(vehicle_command, *session)
        .await
        .expect("the real authority resolves the installed token")
}

/// One staged accepted prompt on the predecessor.
pub(crate) struct PredecessorPrompt {
    command_id: &'static str,
    text: &'static str,
    settled: bool,
}
/// A durable provider answer whose admitted intent has not yet settled.
#[derive(Clone, Copy)]
pub(crate) struct StagedFlight {
    idempotency_key: &'static str,
    command_id: &'static str,
    text: &'static str,
    answer: &'static str,
}

/// One durable owner-DM conversation turn, exactly as the real intake
/// path records it: the Discord surface identity the correlation and
/// command id derive from, the owner request, and the delivered reply.
struct SeededTurn {
    message_id: &'static str,
    request: &'static str,
    answer: &'static str,
}

/// The predecessor conversation's staged history: one settled owner
/// turn durable in the conversation ledger. The bounded brief must
/// carry its request and reply into the fresh harness.
const PRE_HISTORY_TURN: SeededTurn = SeededTurn {
    message_id: PRE_HISTORY_MESSAGE_ID,
    request: "PRE-HISTORY: the owner asked about the registry earlier.",
    answer: "PRE-HISTORY-ANSWER: revision 1 was current earlier.",
};

const OLDER_VEHICLE_TURN_ONE: SeededTurn = SeededTurn {
    message_id: OLDER_VEHICLE_MESSAGE_ID_ONE,
    request: "OLDER-VEHICLE-REQUEST-A: what changed in the registry last week?",
    answer: "OLDER-VEHICLE-REPLY-A: revision 1 published last week.",
};
const OLDER_VEHICLE_TURN_TWO: SeededTurn = SeededTurn {
    message_id: OLDER_VEHICLE_MESSAGE_ID_TWO,
    request: "OLDER-VEHICLE-REQUEST-B: and who reviewed that publication?",
    answer: "OLDER-VEHICLE-REPLY-B: the coordinator seat reviewed it.",
};

/// Seeds one completed owner-DM turn into the durable conversation
/// ledger through the typed record → accept → complete command
/// lifecycle, writing exactly the rows the real intake path writes:
/// the surface-derived idempotency key and intent command id, the
/// Discord message causation, the declared seat target, and the
/// executed terminal projection (causal ids matching the row, the
/// delivered answer, replySent). `sequence` spaces the deterministic
/// timestamps so `terminal_at` orders the staged turns.
fn seed_completed_owner_turn(gate: &GateFixture, turn: &SeededTurn, sequence: u64) {
    let ownership = gate.binding().ownership;
    let discord = gate
        .runtime
        .settings()
        .discord
        .as_ref()
        .expect("declared transport");
    let seat = ownership.seat.as_str();
    let project = ownership.project.as_str();
    let owner_user_id = &discord.owner_user_id;
    let channel_id = &discord.notify_channel_id;
    let capability = &discord.capability;
    let surface = DiscordSurface::new(channel_id, turn.message_id).expect("discord surface");
    let correlation = surface_correlation(&surface).expect("surface correlation");
    let identity = identity_from_key(correlation.idempotency_key.as_str());
    let command_id =
        CommandId::new(format!("{INTENT_COMMAND_PREFIX}{identity}")).expect("intent command id");
    let arguments = serde_json::json!({
        "request": turn.request,
        "channel_id": channel_id,
        "message_id": turn.message_id,
        "author_id": owner_user_id,
        "guild_id": serde_json::Value::Null,
    });
    // Deterministic whole-second stamps: intake precedes acceptance
    // precedes the terminal outcome, and distinct sequences order
    // distinct turns.
    let issued_at = time::OffsetDateTime::from_unix_timestamp(1_767_225_600 + 16 * sequence as i64)
        .expect("staged intake timestamp");
    let spec = CommandSpec {
        id: command_id.clone(),
        idempotency_key: correlation.idempotency_key.clone(),
        correlation_id: correlation.idempotency_key.clone(),
        causation_id: Some(format!("discord:message:{}", turn.message_id)),
        issuer: INTENT_ISSUER.to_owned(),
        approval_id: None,
        target_kind: "seat".to_owned(),
        target_id: seat.to_owned(),
        capability_id: capability.clone(),
        capability_version: 1,
        arguments_hash: Digest::hash(arguments.to_string().as_bytes()),
        arguments,
        expected_desired_revision: None,
        issued_at,
        expires_at: issued_at + time::Duration::seconds(300),
    };
    let mut ledger = odin_ledger::Ledger::open(&gate.ledger_path).expect("conversation ledger");
    let recorded = match ledger
        .record_command(&spec)
        .expect("record the staged owner turn")
    {
        RecordCommand::Inserted(recorded) | RecordCommand::Existing(recorded) => recorded,
    };
    let accepted = ledger
        .accept_command(
            &recorded,
            recorded.command().revision,
            issued_at + time::Duration::seconds(1),
        )
        .expect("accept the staged owner turn");
    let historical_session = session_id_for(
        &CommandId::new(format!("command:historical-vehicle-{sequence}"))
            .expect("historical vehicle command"),
    )
    .expect("historical vehicle identity");
    let outcome = LedgerCommandOutcome {
        status: CommandTerminalStatus::Completed,
        result: serde_json::json!({
            "status": "executed",
            "outcome": {
                "conversationId": format!("conversation:{seat}:{project}"),
                "session": historical_session.to_string(),
                "commandId": command_id.as_str(),
                "idempotencyKey": correlation.idempotency_key,
                "seat": seat,
                "project": project,
                "answer": turn.answer,
                "replySent": true,
            }
        }),
    };
    ledger
        .complete_command(
            &accepted,
            &outcome,
            accepted.command().revision,
            issued_at + time::Duration::seconds(2),
        )
        .expect("settle the staged owner turn");
}

/// Stages the durable predecessor: manifest, the settled owner turn in
/// the conversation ledger (the bounded brief's history source), an
/// optional accepted prompt, an optional admitted-unsettled in-flight
/// intent, and the retained root record naming the deterministic
/// vehicle. The live vehicle journal is staged with NO owner turns:
/// continuity never depends on this vehicle having journaled messages.
pub(crate) async fn stage_predecessor(
    gate: &GateFixture,
    session: &LiveSessionId,
    manifest_binding: Option<u64>,
    vehicle_command: &CommandId,
    admitted_prompt: Option<PredecessorPrompt>,
    staged_flight: Option<StagedFlight>,
) {
    let binding = gate.binding();
    let seat = &binding.ownership.seat;
    let slice = &binding
        .vehicle
        .as_ref()
        .expect("declared vehicle")
        .0
        .slice_id;
    let project = &binding.ownership.project;
    let epoch = SessionEpoch::new(1);
    gate.ledger
        .create_session(SessionManifest {
            session_id: *session,
            seat_id: seat.clone(),
            slice_id: slice.clone(),
            project_id: project.clone(),
            provider: ProviderName::new("gateway").expect("provider"),
            model: ModelName::new("zai-glm").expect("model"),
            title: Some("conversation rollover predecessor".to_owned()),
            target_node: NodeId::new("laptop").expect("node id"),
            open_tab: false,
            workload: None,
            served_revision: manifest_binding,
            harness: None,
        })
        .await
        .expect("stage predecessor session");
    // The settled owner turn lives in the CONVERSATION LEDGER, exactly
    // as the real intake path recorded it — never in this vehicle's
    // journal. Continuity binds to that durable transcript under the
    // fixture's declared seat/project and paired owner/channel.
    seed_completed_owner_turn(gate, &PRE_HISTORY_TURN, 0);
    let event = |id: &str, body| NewLiveEvent {
        session_id: *session,
        event_id: odin_domain::EventId::new(id.to_owned()).expect("history event id"),
        occurred_at: time::OffsetDateTime::now_utc(),
        body,
    };
    let message = |text: &str| {
        LiveMessage::new(vec![LiveContentBlock::Text(text.to_owned())]).expect("history message")
    };
    if let Some(prompt) = admitted_prompt {
        // The supervisor's own lawful admission primitive: the canonical
        // command journal entry for an ACCEPTED prompt, completed only
        // when the row asks for a settled effect.
        let command = LiveCommand {
            command_id: CommandId::new(prompt.command_id).expect("admitted command id"),
            session_id: *session,
            expected_epoch: epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: message(prompt.text),
            },
        };
        gate.ledger
            .append_command(&command)
            .await
            .expect("stage accepted prompt");
        gate.ledger
            .append(
                epoch,
                event(
                    "rollover-pre-prompt",
                    LiveEventBody::UserMessage(message(prompt.text)),
                ),
            )
            .await
            .expect("stage prompt journal event");
        if prompt.settled {
            gate.ledger
                .complete_command(
                    command.command_id.clone(),
                    CommandOutcome::Applied {
                        command_id: command.command_id.clone(),
                    },
                )
                .await
                .expect("settle the staged prompt");
        }
    }
    if let Some(flight) = staged_flight {
        // Journal the answer without recording the command outcome to model interrupted settlement.
        let command = LiveCommand {
            command_id: CommandId::new(flight.command_id).expect("in-flight command id"),
            session_id: *session,
            expected_epoch: epoch,
            expected_event_head: None,
            body: LiveCommandBody::Prompt {
                message: message(flight.text),
            },
        };
        gate.ledger
            .append_command(&command)
            .await
            .expect("stage the admitted in-flight command");
        // The session actor journals the acceptance before the turn runs.
        gate.ledger
            .append(
                epoch,
                event(
                    "rollover-flight-accepted",
                    LiveEventBody::ControlAccepted(odin_domain::huginn::CommandReceipt::Accepted {
                        command_id: command.command_id.clone(),
                    }),
                ),
            )
            .await
            .expect("stage the in-flight acceptance");
        gate.ledger
            .append(
                epoch,
                event(
                    "rollover-flight-prompt",
                    LiveEventBody::UserMessage(message(flight.text)),
                ),
            )
            .await
            .expect("stage the in-flight prompt event");
        gate.ledger
            .append(
                epoch,
                event(
                    "rollover-flight-running",
                    LiveEventBody::SessionStateChanged(odin_domain::huginn::SessionStateChanged {
                        previous: LiveSessionState::Idle,
                        current: LiveSessionState::Running,
                        reason: None,
                    }),
                ),
            )
            .await
            .expect("stage the in-flight running transition");
        gate.ledger
            .append(
                epoch,
                event(
                    "rollover-flight-answer",
                    LiveEventBody::AssistantMessage(message(flight.answer)),
                ),
            )
            .await
            .expect("stage the in-flight journaled answer");
        gate.ledger
            .append(
                epoch,
                event(
                    "rollover-flight-idle",
                    LiveEventBody::SessionStateChanged(odin_domain::huginn::SessionStateChanged {
                        previous: LiveSessionState::Running,
                        current: LiveSessionState::Idle,
                        reason: None,
                    }),
                ),
            )
            .await
            .expect("stage the settled-idle transition");
    }
    // The retained root record, exactly the shape production persists.
    // A staged in-flight intent is the EXACT production record shape:
    // phase=sent persisted at the head BEFORE submission (the session had
    // no events), so the answer wait resumes from cursor 0 — before the
    // command's acceptance and its journaled answer.
    let in_flight = staged_flight.map(|flight| {
        serde_json::json!({
            "idempotencyKey": flight.idempotency_key,
            "content": flight.text,
            "commandId": flight.command_id,
            "sessionId": session.to_string(),
            "kind": "prompt",
            "expectedEpoch": 1,
            "eventCursor": 0,
            "phase": "sent",
        })
    });
    let record = serde_json::json!({
        "conversationId": "",
        "seat": seat.as_str(),
        "project": project.as_str(),
        "vehicleCommandId": vehicle_command.as_str(),
        "sessionId": session.to_string(),
        "inFlight": in_flight,
        "wakes": [],
        "lastIdempotencyKey": serde_json::Value::Null,
        "lastProjection": serde_json::Value::Null,
        "questions": [],
        "updatedAtUnixMs": 0,
    });
    std::fs::write(
        &gate.record_path,
        serde_json::to_vec_pretty(&record).expect("record bytes"),
    )
    .expect("stage retained record");
}

/// Stages one full generation row at revision 1 and REOPENS onto a fresh
/// serving stack: the convergence assertions all drive the reopened stack
/// — the ledger close/reopen path a real daemon restart takes. `advance`
/// publishes revision 2; a row that stays at the current pin omits it.
/// `admitted_prompt` stages a settled accepted prompt (the no-replay
/// surface); `staged_flight` stages an admitted-unsettled in-flight
/// intent (the crash-boundary stranding surface).
pub(crate) async fn stage_row(
    advance: bool,
    admitted_prompt: Option<PredecessorPrompt>,
    staged_flight: Option<StagedFlight>,
) -> GenerationFixture {
    let probe = Arc::new(LaunchProbe::default());
    let launcher = Arc::new(BoundaryLauncher::new(probe.clone()));
    let gate = gate_fixture_with(8, launcher.clone(), false).await;
    gate.runtime
        .bind_notify_sink(probe.clone())
        .expect("isolated egress");

    let binding = gate.binding();
    let (seat_binding, lane) = binding
        .vehicle
        .clone()
        .expect("the fixture binds a vehicle");
    let launch = seat_binding
        .launch_options
        .first()
        .expect("the fixture seat declares a launch pair")
        .clone();
    let authority = DeclaredConversationAuthority {
        config: gate.config.clone(),
        seat: binding.ownership.seat.clone(),
        project: binding.ownership.project.clone(),
        slice: seat_binding.slice_id.clone(),
        lane: lane.clone(),
        provider: launch.provider.clone(),
        model: launch.model.clone(),
        incidents: None,
    };

    let vehicle_command = vehicle_command();
    let session = predecessor_session();
    let worktree = gate._root.path().join("authoring");

    let ensured = mint_installed_token(&authority, &vehicle_command, &session).await;
    assert_eq!(
        ensured.bound, 1,
        "the installed token binds its mint-time pin"
    );
    assert_eq!(ensured.current, 1, "the staging pin is revision 1");

    if advance {
        // The newer publication becomes the current pin.
        publish_revision(&gate, &worktree, 2);
    }

    stage_predecessor(
        &gate,
        &session,
        Some(1),
        &vehicle_command,
        admitted_prompt,
        staged_flight,
    )
    .await;

    let serving = compose_serving(&gate, launcher.clone(), gate.ledger.clone()).await;
    // Path accesses must precede the `gate` move into the fixture.
    let token_file = gate
        .config
        .paths
        .authority_token_root
        .join(format!("{session}.json"));
    let record_path = gate.record_path.clone();
    let mut fixture = GenerationFixture {
        gate,
        probe,
        launcher,
        root: serving.root,
        ledger: serving.ledger,
        authority,
        capsules: Arc::new(AcceptingCapsules),
        vehicle_command,
        session,
        token_file,
        record_path,
    };
    assert!(
        fixture.token_file.is_file(),
        "the real authority provisioned the installed token file"
    );
    fixture.reopen().await;
    fixture
}

/// The same factory configuration with a caller-supplied capsule
/// authority: the wedge-escape fixture composes the REAL session
/// authority pool here, every other seam unchanged.
pub(crate) fn production_factory_config_with(
    gate: &GateFixture,
    live: Arc<dyn LiveLedger>,
    session_capsule_authority: Arc<dyn SessionCapsuleAuthority>,
) -> ProductionBridgeRuntimeConfig {
    let root = gate._root.path();
    let process_dir = root.join("factory-process");
    std::fs::create_dir_all(&process_dir).expect("factory process dir");
    for dir in [
        "factory-worker",
        "factory-bridge",
        "factory-links",
        "factory-artifacts",
        "factory-hooks",
    ] {
        std::fs::create_dir_all(root.join(dir)).expect("factory subdirectory");
    }
    let executable = process_dir.join("omp");
    std::fs::write(&executable, b"").expect("fixture omp executable");
    let spec = OmpProcessSpec {
        executable: executable.clone(),
        cwd: process_dir.clone(),
        explicit_args: vec![
            "--trusted-extension".to_owned(),
            process_dir.join("extension.js").display().to_string(),
            "--no-skills".to_owned(),
            "--no-rules".to_owned(),
            "--no-tools".to_owned(),
            "--no-lsp".to_owned(),
            "--no-pty".to_owned(),
        ],
        explicit_env: vec![("HOME".to_owned(), process_dir.display().to_string())],
        expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
        startup_timeout: StdDuration::from_secs(30),
        drain_timeout: StdDuration::from_secs(5),
        kill_timeout: StdDuration::from_secs(1),
    };
    let digest = Digest::hash(
        std::fs::read(&executable)
            .expect("fixture executable")
            .as_slice(),
    )
    .to_string();
    let hex = digest
        .strip_prefix("blake3:")
        .expect("digest carries the blake3 prefix")
        .to_owned();
    let binding = RegisteredServiceBinding::new(executable.clone(), hex.clone())
        .expect("fixture worker binding");
    let authority_ledger = odin_ledger::Ledger::open(root.join("factory-worker/authority.sqlite3"))
        .expect("worker authority ledger");
    let bus = BusAddress::parse(&gate.config.worker_bus).expect("fixture worker bus from config");
    let bootstrap = process_dir.join("worker-bootstrap");
    let unshare = process_dir.join("unshare");
    std::fs::write(&bootstrap, b"").expect("fixture bootstrap placeholder");
    std::fs::write(&unshare, b"").expect("fixture unshare placeholder");
    let channel = WorkerChannel::new(bus, bootstrap, unshare).expect("fixture worker channel");
    let stop_authority = Arc::new(StopAuthority::new(
        Arc::new(Mutex::new(authority_ledger)),
        channel,
    ));
    let correlation_hex = Digest::hash(format!("rollover-fixture\0{hex}").as_bytes()).to_string();
    let correlation =
        CorrelationId::new(&correlation_hex["blake3:".len()..][..32]).expect("fixture correlation");
    let worker = OmpWorkerLaunch::new(
        stop_authority,
        correlation,
        "odin-readmission",
        "odin-rollover-fixture".to_owned(),
        1,
        binding,
        ScopeLimits {
            lifetime: odin_process::ScopeLifetime::Bounded(StdDuration::from_secs(960)),
            timeout_stop: StdDuration::from_secs(5),
            ..ScopeLimits::default()
        },
    )
    .expect("fixture worker launch");

    // The real retained-publication recomposition and the real provisioned
    // authority: exactly the daemon's own components over the fixture's
    // published registry and provisioned key.
    let revision_material = Arc::new(odin_cli::runtime_bindings::StoreRevisionMaterial::new(
        SnapshotStore::new(&gate.config.paths.registry_snapshot),
        gate.config.clone(),
    ));
    // The seat/lane served sets derive from the SAME published snapshot the
    // resolver recomposes: no hand-built policy anywhere.
    let (seat_operation_bindings, session_lanes) = {
        let material = odin_omp::host_tools::operations::RevisionMaterialSource::material_at(
            revision_material.as_ref(),
            1,
        )
        .expect("recompose revision 1 material");
        (material.seat_operation_bindings, material.session_lanes)
    };
    let key = std::fs::read(&gate.config.paths.authority_verification_key_file)
        .expect("read the provisioned authority key");

    ProductionBridgeRuntimeConfig {
        workload_drafts: None,
        task_grants: None,
        process: spec,
        worker,
        // Production shares ONE session-state sqlite between the bridge
        // launch (which creates the durable run:live:<session> row the
        // conversation plan gate reads) and every other surface: the
        // fixture mirrors that exactly.
        bridge_ledger: Arc::new(Mutex::new(
            odin_ledger::Ledger::open(gate.ledger_path.clone())
                .expect("bridge ledger over the shared session state"),
        )),
        live_ledger: live,
        atlas: Arc::new(
            odin_atlas::build(odin_atlas::AtlasSources::new(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
            ))
            .expect("atlas composes over the repository"),
        ),
        allowed_atlas_scope: odin_atlas::AtlasScope::default(),
        brain_policies: BTreeMap::new(),
        brain_sources: BTreeMap::new(),
        brain_embedding: None,
        brain_embedding_model: None,
        brain_postgres: None,
        artifact_root: root.join("factory-artifacts"),
        max_artifact_read_bytes: 4096,
        project_roots: BTreeMap::from([(
            gate.binding().ownership.project.clone(),
            root.join("projects/research"),
        )]),
        session_lanes,
        allowed_nodes: BTreeSet::from([NodeId::new("laptop").expect("node id")]),
        read_only: false,
        owner_id: "odind:rollover-fixture".to_owned(),
        hooks_root: root.join("factory-hooks"),
        lease_ttl: StdDuration::from_secs(60),
        zellij: None,
        operation_contracts: BTreeMap::new(),
        operator_capabilities: odin_cli::runtime_bindings::OPERATOR_CAPABILITY_BINDINGS
            .iter()
            .map(|binding| {
                odin_domain::CapabilityId::new(binding.capability)
                    .expect("compiled operator capability id is valid")
            })
            .collect(),
        admission_revision: 1,
        schema_catalog: Arc::new(StaticSchemaCatalog::new(Vec::new()).expect("schema catalog")),
        operation_limits: odin_domain::operation::Limits::new(u64::MAX, u64::MAX, u64::MAX),
        operation_clock: wall_clock(),
        task_slot: None,
        operation_authority_provider: Arc::new(
            ProvisionedFreshAuthorityProvider::open(
                gate.config.paths.authority_token_root.clone(),
                key,
            )
            .expect("open the provisioned authority provider"),
        ),
        revision_material,
        adapters: Arc::new(odin_omp::host_tools::adapter::DeclaredAdapterBackends::none()),
        adapter_status_ttl: StdDuration::from_secs(1),
        session_capsule_authority,
        seat_operation_bindings,
        delegation_links: DelegationLinkLedger::open(root.join("factory-links"))
            .expect("delegation links"),
        rollover_by_seat: BTreeMap::new(),
        lane_windows_by_seat: BTreeMap::new(),
        conversation_guidance: BTreeMap::new(),
        tool_exposure: BTreeMap::new(),
        workload_sessions: BTreeMap::new(),
        workload_carrier: None,
        context_read: None,
        hermes_tools: Vec::new(),
        hermes_internal_bindings: Vec::new(),
        seat_sandboxes: BTreeMap::new(),
        seat_memory_max: BTreeMap::new(),
        sandbox_host: None,
    }
}

/// One composed serving stack: the conversation root and the live
/// ledger it serves over.
pub(crate) struct ServingStack {
    pub(crate) root: Arc<odin_hermes::conversation::ConversationRoot>,
    pub(crate) ledger: Arc<dyn LiveLedger>,
    pub(crate) plane: Arc<OmpLiveService>,
}

/// Composes the REAL serving stack over the fixture's durable state: a
/// fresh file-backed ledger, the production factory behind the boundary
/// launcher, the supervisor, the real plane, and the real conversation
/// root over the SAME retained record.
async fn compose_serving(
    gate: &GateFixture,
    launcher: Arc<BoundaryLauncher>,
    live: Arc<dyn LiveLedger>,
) -> ServingStack {
    compose_serving_with(gate, launcher, live, Arc::new(AcceptingCapsules)).await
}

pub(crate) async fn compose_serving_with(
    gate: &GateFixture,
    launcher: Arc<BoundaryLauncher>,
    live: Arc<dyn LiveLedger>,
    session_capsule_authority: Arc<dyn SessionCapsuleAuthority>,
) -> ServingStack {
    let factory = Arc::new(
        ProductionBridgeRuntimeFactory::restricted(
            production_factory_config_with(gate, live.clone(), session_capsule_authority),
            Vec::new(),
        )
        .expect("the production factory composes over the fixture"),
    );
    launcher.arm(factory);
    let supervisor = LiveSupervisor::new(live.clone(), launcher, 8, None);
    let (seat_binding, _) = {
        let declared = gate.binding();
        declared
            .vehicle
            .clone()
            .expect("the fixture binds a vehicle")
    };
    supervisor
        .bind(seat_binding)
        .await
        .expect("bind the fixture seat");
    let resolver = Arc::new(RegistryTransferLaneResolver::read_only(live.clone()));
    let lane_port = Arc::new(
        FsLaneArtifactPort::open(gate._root.path().join("lane-artifacts"))
            .expect("lane artifact port"),
    );
    let bridge = Arc::new(LaneTransferBridge::new(lane_port));
    let transfers = Arc::new(
        TransferManager::open(
            gate._root.path().join("live-transfers"),
            live.clone(),
            resolver,
            bridge,
        )
        .expect("transfer manager"),
    );
    let omp = Arc::new(OmpLiveService::new(live.clone(), supervisor, transfers));
    let root = compose_root_at(gate, &omp, gate.record_path.clone());
    ServingStack {
        root,
        ledger: live,
        plane: omp,
    }
}

/// Reproduce vehicle-open composition, which is private to the serving module.
pub(crate) fn compose_root_at(
    gate: &GateFixture,
    omp: &Arc<OmpLiveService>,
    state_path: PathBuf,
) -> Arc<odin_hermes::conversation::ConversationRoot> {
    let declared = gate.binding();
    let declaration = declared.declaration.clone();
    let (seat_binding, lane) = declared
        .vehicle
        .clone()
        .expect("the fixture binds a vehicle");
    let runtime = Arc::clone(&gate.runtime);
    let discord = runtime
        .settings()
        .discord
        .clone()
        .expect("the armed fixture declares its transport");
    let launch = seat_binding
        .launch_options
        .first()
        .expect("the fixture seat declares a launch pair")
        .clone();
    let target_node =
        odin_domain::NodeId::new(&gate.config.identity.node).expect("the fixture serving node");
    let approval_ledger =
        odin_ledger::Ledger::open(&gate.ledger_path).expect("conversation approval ledger");
    // The declared authority is composed FIRST: the config literal below
    // moves seat_binding, lane, and the launch pair into the root, so
    // every value the authority needs is cloned before those moves.
    let authority = Arc::new(DeclaredConversationAuthority {
        config: gate.config.clone(),
        seat: seat_binding.seat_id.clone(),
        project: declaration.project.clone(),
        slice: seat_binding.slice_id.clone(),
        lane: lane.clone(),
        provider: launch.provider.clone(),
        model: launch.model.clone(),
        incidents: None,
    });
    odin_hermes::conversation::ConversationRoot::open(
        odin_hermes::conversation::ConversationRootConfig {
            binding: seat_binding,
            project: declaration.project.clone(),
            lane,
            provider: launch.provider,
            model: launch.model,
            target_node,
            owner: odin_hermes::conversation::OwnerSurface {
                owner_user_id: discord.owner_user_id.clone(),
                channel_id: discord.notify_channel_id.clone(),
                actor: format!("discord-owner:{}", discord.owner_user_id),
            },
            answer_bound: StdDuration::from_secs(declaration.answer_timeout_seconds.get()),
            poll_interval: StdDuration::from_secs(2),
            plane: omp.clone(),
            authority,
            egress: Arc::new(Arc::downgrade(&runtime)),
            approvals: Arc::new(odin_hermes::conversation::DaemonKernelApprovals {
                runtime: Arc::downgrade(&runtime),
                ledger: Arc::new(parking_lot::Mutex::new(approval_ledger)),
                delegation_links: None,
            }),
            ledger_path: gate.ledger_path.clone(),
            state_path,
            rollover: odin_omp::live::rollover::RolloverPolicy::default(),
            clock: None,
            delegation_links: None,
        },
    )
    .expect("the armed surface composes the conversation root")
}

/// Bounded DM execution: the internal answer wait is bounded by the
/// declared answer timeout; the outer bound keeps a broken vehicle from
/// parking the suite.
pub(crate) async fn execute_dm(
    fixture: &GenerationFixture,
    idempotency_key: &str,
) -> serde_json::Value {
    let execution = ApprovedIntentExecution {
        command_id: format!("command:intent:{idempotency_key}"),
        idempotency_key: idempotency_key.to_owned(),
        content: DM_PAYLOAD.to_owned(),
        unprompted: false,
    };
    tokio::time::timeout(StdDuration::from_secs(30), fixture.root.execute(execution))
        .await
        .expect("the DM settles within the suite bound")
        .expect("the DM execution succeeds")
}

/// The durable rollover slot from the retained record: the successor
/// identities, their phase, and the persisted brief.
fn recorded_rollover(fixture: &GenerationFixture) -> serde_json::Value {
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.record_path).expect("retained record"))
            .expect("retained record parses");
    record["rollover"].clone()
}

/// [focus] The lagging rev-1 vehicle rolls to a FRESH current-generation
/// session across the reopen: predecessor terminally retired and
/// untouched, successor bound to rev 2, the rollover brief injected as
/// the fresh harness's first prompt with the predecessor's staged
/// history, settled effects never replayed, and the first DM answered
/// message-specific.
#[tokio::test]
async fn lagging_vehicle_rolls_to_fresh_current_generation() {
    let mut fixture = stage_row(
        true,
        Some(PredecessorPrompt {
            command_id: "command:intent:rollover-pre-accepted",
            text: PRE_DM_TEXT,
            settled: true,
        }),
        None,
    )
    .await;
    let token_before = std::fs::read(&fixture.token_file).expect("installed token");
    let predecessor = fixture.session;

    fixture
        .root
        .initialize()
        .await
        .expect("startup rolls the lagging vehicle to the current generation");

    // The durable slot names BOTH identities and settles open.
    let slot = recorded_rollover(&fixture);
    assert_eq!(
        slot["predecessorSession"],
        predecessor.to_string(),
        "the slot names the retired predecessor"
    );
    assert_eq!(
        slot["phase"], "open",
        "the transition settles only after the successor open is durable"
    );
    assert!(
        slot["brief"].is_string(),
        "the bounded brief persists in the slot before the successor open"
    );
    let successor: LiveSessionId = LiveSessionId::parse(
        slot["successorSession"]
            .as_str()
            .expect("the slot names the successor"),
    )
    .expect("successor session id");
    assert_ne!(
        successor, predecessor,
        "the rollover converges on a FRESH current-generation session"
    );
    assert_eq!(
        fixture
            .root
            .current_vehicle_session()
            .await
            .expect("vehicle readable")
            .expect("vehicle recorded"),
        successor,
        "the record names the successor as the vehicle"
    );

    // The predecessor is terminally retired and NEVER rebound: its durable
    // manifest keeps its original binding and its token file is untouched.
    let predecessor_row = fixture
        .ledger
        .session(predecessor)
        .await
        .expect("predecessor row");
    assert_eq!(
        predecessor_row.manifest.served_revision,
        Some(1),
        "the retired predecessor's manifest binding is never rewritten"
    );
    assert!(is_terminal(&fixture, predecessor).await);
    assert_eq!(
        std::fs::read(&fixture.token_file).expect("installed token"),
        token_before,
        "the retired predecessor's token is never reminted"
    );
    // The predecessor's ensured report STILL reports its frozen bound
    // against the new pin: the token was untouched, never rebinding it.
    let predecessor_ensured = ensured(&fixture, &fixture.vehicle_command, &predecessor).await;
    assert_eq!(
        predecessor_ensured.bound, 1,
        "the predecessor token keeps its claim"
    );
    assert_eq!(
        predecessor_ensured.current, 2,
        "the pin moved to revision 2"
    );

    // The successor is bound to the CURRENT generation: manifest and
    // token claim both name rev 2, through the real authority and the
    // real resolver.
    let successor_command = CommandId::new(
        slot["successorCommand"]
            .as_str()
            .expect("the slot names the successor command"),
    )
    .expect("successor command id");
    let successor_row = fixture
        .ledger
        .session(successor)
        .await
        .expect("successor row");
    assert_eq!(
        successor_row.manifest.served_revision,
        Some(2),
        "the fresh session's manifest binds the current publication"
    );
    let successor_ensured = ensured(&fixture, &successor_command, &successor).await;
    assert_eq!(
        successor_ensured.bound, 2,
        "the fresh session's token claims the current publication"
    );
    assert_eq!(
        successor_ensured.current, 2,
        "the successor resolves at the current pin"
    );

    // The continuity brief reached the FRESH harness: the successor's
    // first prompt carries the rollover-brief schema and the predecessor's
    // staged history; the settled predecessor prompt never replays.
    let prompts = fixture.probe.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "exactly the successor's initial prompt: {prompts:?}"
    );
    let brief: serde_json::Value = serde_json::from_str(
        prompts[0]
            .split_once('\n')
            .expect("brief header and payload")
            .1,
    )
    .expect("the successor's initial prompt carries the rollover brief JSON");
    assert_eq!(
        brief["schema"], "odin.rollover-brief.v1",
        "the brief carries the rollover-brief schema"
    );
    assert!(
        prompts[0].contains("PRE-HISTORY"),
        "the bounded brief carries the predecessor history into the fresh harness"
    );
    // The settled predecessor prompt is never REISSUED: its admitted,
    // settled command journal effect stays retired, so its text may
    // appear at most inside the required first prompt.
    let brief_prompt = prompts[0].clone();
    assert!(
        prompts
            .iter()
            .all(|prompt| *prompt == brief_prompt || !prompt.contains(PRE_DM_TEXT)),
        "an accepted, settled effect is never replayed as a fresh prompt: {prompts:?}"
    );

    // The FIRST post-publication DM rides the fresh session and is
    // answered with message-specific content.
    let dm_projection = execute_dm(&fixture, "rollover-post-dm-1").await;
    assert_eq!(
        dm_projection["answer"], DM_REPLY,
        "the owner gets the message-specific reply, not a brief or open echo"
    );
    assert_eq!(
        dm_projection["replySent"], true,
        "the reply delivery is recorded"
    );
    assert!(fixture
        .probe
        .delivered
        .lock()
        .expect("deliveries")
        .iter()
        .any(|message| message.content == DM_REPLY));
    assert_eq!(
        fixture.probe.prompt_count(DM_PAYLOAD),
        1,
        "the DM rides the fresh session exactly once"
    );

    let replay = execute_dm(&fixture, "rollover-post-dm-1").await;
    assert_eq!(
        replay, dm_projection,
        "the replay returns the recorded projection"
    );
    assert_eq!(
        fixture.probe.prompt_count(DM_PAYLOAD),
        1,
        "no re-prompt on the replayed key"
    );
    // SECOND publication, SAME test loop: the completed transition never
    // blocks the next one. Rev 3 rolls the rev-2 successor to a rev-3
    // session with the same laws — the rev-2 predecessor retires Ended
    // with its manifest untouched, and the fresh session binds rev 3.
    publish_revision(
        &fixture.gate,
        &fixture.gate._root.path().join("authoring"),
        3,
    );
    fixture.reopen().await;
    fixture
        .root
        .initialize()
        .await
        .expect("startup rolls the rev-2 vehicle to revision 3");
    let second_slot = recorded_rollover(&fixture);
    let second_successor: LiveSessionId = LiveSessionId::parse(
        second_slot["successorSession"]
            .as_str()
            .expect("the second slot names its successor"),
    )
    .expect("second successor session id");
    assert_ne!(
        second_successor, successor,
        "each publication rolls a FRESH session"
    );
    assert_eq!(
        second_slot["predecessorSession"],
        successor.to_string(),
        "the second transition retires the rev-2 session"
    );
    let second_row = fixture
        .ledger
        .session(second_successor)
        .await
        .expect("second successor row");
    assert_eq!(
        second_row.manifest.served_revision,
        Some(3),
        "the second fresh session binds revision 3"
    );
    let second_command = CommandId::new(
        second_slot["successorCommand"]
            .as_str()
            .expect("the second slot names its successor command"),
    )
    .expect("second successor command id");
    let second_ensured = ensured(&fixture, &second_command, &second_successor).await;
    assert_eq!(
        second_ensured.bound, 3,
        "the second fresh session's token claims revision 3"
    );
    assert_eq!(
        second_ensured.current, 3,
        "the second successor resolves at revision 3"
    );
    let rev2_row = fixture.ledger.session(successor).await.expect("rev-2 row");
    assert_eq!(
        rev2_row.manifest.served_revision,
        Some(2),
        "the rev-2 predecessor's manifest is never rebound"
    );
    let dm_on_second = execute_dm(&fixture, "rollover-post-dm-2").await;
    assert_eq!(
        dm_on_second["answer"], DM_REPLY,
        "the owner keeps getting message-specific answers across publications"
    );
}

/// Rollover history comes from the conversation transcript, even without turns in the live journal.
#[tokio::test]
async fn lifecycle_only_predecessor_rolls_with_durable_older_vehicle_turns() {
    let fixture = stage_row(true, None, None).await;
    let token_before = std::fs::read(&fixture.token_file).expect("installed token");
    let predecessor = fixture.session;

    // The OLDER vehicles' durable turns: completed intake commands in
    // the conversation ledger, seeded through the typed record →
    // accept → complete lifecycle under the fixture's declared
    // seat/project and paired owner/channel. The rows name older
    // vehicles — logical continuity survives vehicle changes.
    for (sequence, turn) in [&OLDER_VEHICLE_TURN_ONE, &OLDER_VEHICLE_TURN_TWO]
        .into_iter()
        .enumerate()
    {
        seed_completed_owner_turn(&fixture.gate, turn, sequence as u64 + 1);
    }

    // Populate lifecycle history without any user turns.
    for step in 0..402u64 {
        let (previous, current) = if step % 2 == 0 {
            (LiveSessionState::Idle, LiveSessionState::Running)
        } else {
            (LiveSessionState::Running, LiveSessionState::Idle)
        };
        fixture
            .ledger
            .append(
                SessionEpoch::new(1),
                NewLiveEvent {
                    session_id: predecessor,
                    event_id: odin_domain::EventId::new(format!("rollover-lifecycle-{step}"))
                        .expect("lifecycle event id"),
                    occurred_at: time::OffsetDateTime::now_utc(),
                    body: LiveEventBody::SessionStateChanged(
                        odin_domain::huginn::SessionStateChanged {
                            previous,
                            current,
                            reason: None,
                        },
                    ),
                },
            )
            .await
            .expect("stage the lifecycle-only journal");
    }

    fixture
        .root
        .initialize()
        .await
        .expect("a vehicle with no journaled turns still rolls to the current generation");

    // The transition completed: fresh successor, predecessor retired.
    let slot = recorded_rollover(&fixture);
    assert_eq!(
        slot["phase"], "open",
        "the lifecycle-only vehicle still completes its rollover: {slot}"
    );
    assert_eq!(
        slot["predecessorSession"],
        predecessor.to_string(),
        "the slot names the retired lifecycle-only predecessor"
    );
    let successor: LiveSessionId = LiveSessionId::parse(
        slot["successorSession"]
            .as_str()
            .expect("the slot names the successor"),
    )
    .expect("successor session id");
    assert_ne!(
        successor, predecessor,
        "the rollover still converges on a fresh current-generation session"
    );

    // The brief reached the fresh harness with BOTH the actual request
    // and the actual reply of each durable turn, oldest first.
    let prompts = fixture.probe.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "exactly the successor's initial brief prompt: {prompts:?}"
    );
    assert!(prompts[0].starts_with(odin_omp::live::rollover::ROLLOVER_PROMPT_MARKER));
    let brief: serde_json::Value = serde_json::from_str(
        prompts[0]
            .split_once('\n')
            .expect("brief header and payload")
            .1,
    )
    .expect("the successor's initial prompt carries the rollover brief JSON");
    assert_eq!(
        brief["schema"], "odin.rollover-brief.v1",
        "the brief carries the rollover-brief schema"
    );
    let carried = |needle: &str| {
        prompts[0]
            .find(needle)
            .unwrap_or_else(|| panic!("the brief carries the durable turn text {needle:?}"))
    };
    assert!(carried("PRE-HISTORY: the owner asked") < carried(OLDER_VEHICLE_TURN_ONE.request));
    assert!(carried(OLDER_VEHICLE_TURN_ONE.request) < carried(OLDER_VEHICLE_TURN_ONE.answer));
    assert!(carried(OLDER_VEHICLE_TURN_ONE.answer) < carried(OLDER_VEHICLE_TURN_TWO.request));
    assert!(carried(OLDER_VEHICLE_TURN_TWO.request) < carried(OLDER_VEHICLE_TURN_TWO.answer));

    // The next DM still rides the fresh session and is answered
    // message-specifically.
    let dm = execute_dm(&fixture, "lifecycle-post-dm-1").await;
    assert_eq!(
        dm["answer"], DM_REPLY,
        "the owner still gets the message-specific reply"
    );
    assert_eq!(dm["replySent"], true, "the reply delivery is recorded");

    // The retired predecessor keeps its frozen binding and untouched
    // token: continuity moved nothing but the vehicle.
    let predecessor_row = fixture
        .ledger
        .session(predecessor)
        .await
        .expect("predecessor row");
    assert_eq!(
        predecessor_row.manifest.served_revision,
        Some(1),
        "the retired predecessor's manifest binding is frozen"
    );
    assert!(is_terminal(&fixture, predecessor).await);
    assert_eq!(
        std::fs::read(&fixture.token_file).expect("installed token"),
        token_before,
        "the retired predecessor's token is never reminted"
    );
}

/// [crash analogue] The crash AFTER the predecessor's governed close and
/// the durable slot switch, BEFORE the successor open becomes durable: a
/// Pending slot over a retired predecessor resumes on the next startup —
/// the root is never bricked, the fresh session opens bound to the
/// current generation, and the conversation keeps answering.
#[tokio::test]
async fn crash_after_predecessor_close_resumes_the_pending_slot() {
    let mut fixture = stage_row(true, None, None).await;
    let predecessor = fixture.session;

    // The ONE crash analogue: the successor launch refuses before any
    // effect — a daemon death between the predecessor close and the
    // durable successor open.
    fixture.launcher.fail_next_open();
    fixture
        .root
        .initialize()
        .await
        .expect_err("the crashed successor open surfaces at startup");

    // The interrupted transition is durably Pending over the retired
    // predecessor: the slot, the switch, and the closure all survived.
    let slot = recorded_rollover(&fixture);
    assert_eq!(
        slot["phase"], "pending",
        "the interrupted transition stays Pending: {slot}"
    );
    assert_eq!(
        slot["predecessorSession"],
        predecessor.to_string(),
        "the pending slot names the retired predecessor"
    );
    assert!(is_terminal(&fixture, predecessor).await);

    // The NEXT startup resumes the SAME pinned transition verbatim.
    fixture.reopen().await;
    fixture
        .root
        .initialize()
        .await
        .expect("the resumed rollover converges");
    let prompts = fixture.probe.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "resume admits the missing first context exactly once"
    );
    assert!(prompts[0].starts_with(odin_omp::live::rollover::ROLLOVER_PROMPT_MARKER));
    let successor: LiveSessionId = LiveSessionId::parse(
        recorded_rollover(&fixture)["successorSession"]
            .as_str()
            .expect("the resumed slot names its successor"),
    )
    .expect("successor session id");
    let successor_row = fixture
        .ledger
        .session(successor)
        .await
        .expect("successor row");
    assert_eq!(
        successor_row.manifest.served_revision,
        Some(2),
        "the resumed successor binds the current publication"
    );
    let dm = execute_dm(&fixture, "crash-resume-dm-1").await;
    assert_eq!(
        dm["answer"], DM_REPLY,
        "the conversation keeps answering after the resume"
    );
}

/// [admitted-unsettled crash boundary] The predecessor really admitted
/// an intent (a command journal entry), its provider answer is already
/// durable, and the root crashed before settling it. The rollover
/// strands the admitted command EXACTLY where it was admitted — the
/// record keeps naming the predecessor and the successor is never
/// prompted with it — the journaled answer settles it on the next
/// intent, and the next fresh DM is accepted on the successor.
#[tokio::test]
async fn admitted_unsettled_intent_stays_on_predecessor_across_rollover() {
    let staged = StagedFlight {
        idempotency_key: "rollover-in-flight-1",
        command_id: "command:intent:rollover-in-flight-1",
        text: IN_FLIGHT_TEXT,
        answer: IN_FLIGHT_ANSWER,
    };
    let staged_command_id = staged.command_id;
    let fixture = stage_row(true, None, Some(staged)).await;
    let predecessor = fixture.session;

    fixture
        .root
        .initialize()
        .await
        .expect("startup rolls the lagging vehicle with its admitted intent stranded");

    // The admitted intent stays durably in flight ON THE PREDECESSOR:
    // never retargeted, never re-admitted onto the successor.
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.record_path).expect("retained record"))
            .expect("retained record parses");
    let flight = &record["inFlight"];
    assert!(
        flight.is_object(),
        "the admitted intent stays durably in flight: {record}"
    );
    assert_eq!(
        flight["sessionId"],
        predecessor.to_string(),
        "the admitted command stays stranded on its admitting session"
    );
    assert_eq!(
        flight["commandId"], staged_command_id,
        "the stranded intent is the exact admitted command"
    );
    let stranded_command = LiveCommand {
        command_id: CommandId::new(staged_command_id).expect("stranded command id"),
        session_id: predecessor,
        expected_epoch: SessionEpoch::new(1),
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message: LiveMessage::new(vec![LiveContentBlock::Text(IN_FLIGHT_TEXT.to_owned())])
                .expect("stranded message"),
        },
    };
    let entry = fixture
        .ledger
        .command(&stranded_command)
        .await
        .expect("the command journal is readable")
        .expect("the admission survives the transition");
    assert_eq!(
        entry.command.session_id, predecessor,
        "the journal keeps the admitted command on the predecessor"
    );

    // The fresh harness saw exactly ONE prompt: the required brief. The
    // admitted prompt text appears only as history inside it — never as
    // a separately reissued prompt.
    let prompts = fixture.probe.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "exactly the successor's initial brief prompt: {prompts:?}"
    );
    let brief: serde_json::Value = serde_json::from_str(
        prompts[0]
            .split_once('\n')
            .expect("brief header and payload")
            .1,
    )
    .expect("the successor's initial prompt carries the rollover brief JSON");
    assert_eq!(
        brief["schema"], "odin.rollover-brief.v1",
        "the brief carries the rollover-brief schema"
    );
    let brief_prompt = prompts[0].clone();
    assert!(
        prompts
            .iter()
            .all(|prompt| *prompt == brief_prompt || !prompt.contains(IN_FLIGHT_TEXT)),
        "the admitted prompt is never reissued as a fresh prompt: {prompts:?}"
    );

    // Resuming the admitted key observes its original journal, never the
    // successor's unrelated brief response.
    let resumed = fixture
        .root
        .execute(ApprovedIntentExecution {
            command_id: staged.command_id.to_owned(),
            idempotency_key: staged.idempotency_key.to_owned(),
            content: staged.text.to_owned(),
            unprompted: false,
        })
        .await
        .expect("the admitted intent observes its predecessor answer");
    assert_eq!(resumed["answer"], IN_FLIGHT_ANSWER);
    assert_eq!(resumed["session"], predecessor.to_string());
    assert_eq!(fixture.probe.prompts(), prompts);

    // A new intent is answered message-specifically on the successor.
    let dm = execute_dm(&fixture, "rollover-after-in-flight-1").await;
    assert_eq!(
        dm["answer"], DM_REPLY,
        "the conversation keeps accepting fresh intents after the crash boundary"
    );
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.record_path).expect("retained record"))
            .expect("retained record parses");
    assert!(
        record["inFlight"].is_null(),
        "the settled stranded flight left the record: {record}"
    );
    assert_eq!(
        record["lastIdempotencyKey"], "rollover-after-in-flight-1",
        "the fresh intent is the recorded settlement"
    );
}
/// [already-current] A coherent pair AT the current pin recovers in
/// place: SAME session id, plain reclaim, no rollover slot, no closure,
/// and no token touch.
#[tokio::test]
async fn already_current_pair_recovers_in_place_without_rollover() {
    let fixture = stage_row(false, None, None).await;
    let token_before = std::fs::read(&fixture.token_file).expect("installed token");
    let predecessor = fixture.session;

    let ensured_before = ensured(&fixture, &fixture.vehicle_command, &predecessor).await;
    assert_eq!(ensured_before.bound, 1, "the token binds its generation");
    assert_eq!(ensured_before.current, 1, "the pin is still revision 1");

    fixture
        .root
        .initialize()
        .await
        .expect("startup recovers the already-current pair in place");

    // SAME identity, plain reclaim.
    assert_eq!(
        fixture
            .root
            .current_vehicle_session()
            .await
            .expect("vehicle readable")
            .expect("vehicle recorded"),
        predecessor,
        "an already-current pair never switches identity"
    );
    let slot = recorded_rollover(&fixture);
    assert!(
        slot.is_null(),
        "no rollover slot is staged for a coherent current pair: {slot}"
    );
    let opens = fixture.probe.opens();
    assert_eq!(
        opens.len(),
        1,
        "exactly the in-place reclaim open: {opens:?}"
    );
    let open = opens.first().expect("the reclaim open");
    assert_eq!(open.session, predecessor);
    assert!(open.reclaim, "the recovery rides the reclaim surface");
    assert_eq!(open.epoch, 2, "the reclaim bumps the epoch exactly once");
    let durable = fixture
        .ledger
        .session(predecessor)
        .await
        .expect("session row");
    assert_eq!(
        durable.epoch,
        SessionEpoch::new(2),
        "the durable epoch moved to 2"
    );
    assert!(!is_terminal(&fixture, predecessor).await);
    assert_eq!(
        std::fs::read(&fixture.token_file).expect("installed token"),
        token_before,
        "an already-current recovery never remints the token"
    );
}

/// A reverted seat declaration models unchanged composition because this fixture has no routine-capable seat.
#[tokio::test]
async fn a_composition_identical_publication_keeps_the_vehicle_and_a_seat_change_lags() {
    let fixture = stage_row(false, None, None).await;
    let predecessor = fixture.session;
    let worktree = fixture.gate._root.path().join("authoring");
    let seat_toml = worktree.join("registry/seats/coordinator/seat.toml");
    let original = std::fs::read(&seat_toml).expect("fixture seat toml");

    publish_revision(&fixture.gate, &worktree, 2);
    let changed = ensured(&fixture, &fixture.vehicle_command, &predecessor).await;
    assert_eq!((changed.bound, changed.current), (1, 2));
    assert!(
        changed.composition.is_some(),
        "the retained store proves both digests: {changed:?}"
    );
    assert!(changed.lags(), "a seat change still lags: {changed:?}");

    std::fs::write(&seat_toml, &original).expect("revert the seat");
    publish_worktree(&fixture.gate, &worktree, 3);
    let kept = ensured(&fixture, &fixture.vehicle_command, &predecessor).await;
    assert_eq!((kept.bound, kept.current), (1, 3), "the pin advanced");
    assert!(
        kept.kept_composition().is_some(),
        "the revert composes the vehicle as its bound did: {kept:?}"
    );
    assert!(
        !kept.lags(),
        "an unchanged composition never lags the vehicle"
    );

    fixture
        .root
        .initialize()
        .await
        .expect("startup recovers the composition-current vehicle in place");
    assert_eq!(
        fixture
            .root
            .current_vehicle_session()
            .await
            .expect("vehicle readable")
            .expect("vehicle recorded"),
        predecessor,
        "an unchanged composition never switches the vehicle"
    );
    assert!(
        recorded_rollover(&fixture).is_null(),
        "no rollover slot for an unchanged composition"
    );
}

/// [terminal boundary] A truthfully Ended predecessor refuses startup
/// typed before any rollover: no fresh session opens, the identity is
/// never rebound, and the closed token is never touched.
#[tokio::test]
async fn closed_predecessor_never_rolls_even_when_lagging() {
    let fixture = stage_row(true, None, None).await;
    let token_before = std::fs::read(&fixture.token_file).expect("installed token");
    fixture
        .ledger
        .append(
            SessionEpoch::new(1),
            NewLiveEvent {
                session_id: fixture.session,
                event_id: odin_domain::EventId::new("rollover-closed-predecessor".to_owned())
                    .expect("closure event id"),
                occurred_at: time::OffsetDateTime::now_utc(),
                body: LiveEventBody::SessionClosed(odin_domain::huginn::SessionClosed {
                    reason: odin_domain::huginn::SessionCloseReason::Completed,
                }),
            },
        )
        .await
        .expect("close the predecessor");

    let refused = fixture
        .root
        .initialize()
        .await
        .expect_err("a terminally closed vehicle refuses startup");
    assert!(
        matches!(
            refused,
            odin_hermes::conversation::InitializeError::TerminalClosed { .. }
        ),
        "the typed terminal closure precedes any rollover: {refused:?}"
    );
    assert!(
        fixture.probe.opens().is_empty(),
        "a closed vehicle never opens a fresh session"
    );
    assert_eq!(
        std::fs::read(&fixture.token_file).expect("installed token"),
        token_before,
        "a closed vehicle's token is never migrated"
    );
    let durable = fixture
        .ledger
        .session(fixture.session)
        .await
        .expect("session row");
    assert_eq!(
        durable.manifest.served_revision,
        Some(1),
        "a closed vehicle's manifest is never rebound"
    );
    let slot = recorded_rollover(&fixture);
    assert!(
        slot.is_null(),
        "no rollover slot is staged for a closed vehicle: {slot}"
    );
}

/// A definitively failed admitted brief must not wedge the vehicle forever.
/// Unlike a transport loss (whose dispatch outcome is unknown), a negative
/// backend response settles Failed in the real command journal. That command
/// is never replayed under its own id; a fresh successor carries the same brief.
#[tokio::test]
async fn failed_admitted_brief_supersedes_to_a_fresh_successor_without_replay() {
    let fixture = stage_row(true, None, None).await;
    fixture.probe.reject_prompt.store(true, Ordering::SeqCst);
    fixture
        .root
        .initialize()
        .await
        .expect("a definitively failed brief moves to a fresh successor, not a wedge");
    let prompts = fixture.probe.prompts();
    assert_eq!(
        prompts.len(),
        2,
        "the failed brief is followed by exactly one fresh successor's brief"
    );
    assert_eq!(
        fixture.probe.opens().len(),
        2,
        "the failed successor and the fresh successor each opened once"
    );
    assert_eq!(recorded_rollover(&fixture)["phase"], "open");
    assert_eq!(prompts[0], prompts[1], "the brief survives verbatim");
    let opens = fixture.probe.opens();
    assert_ne!(opens[0].session, opens[1].session);
    assert!(is_terminal(&fixture, opens[0].session).await);
    let slot = recorded_rollover(&fixture);
    assert_eq!(slot["predecessorSession"], opens[0].session.to_string());
    assert_eq!(slot["successorSession"], opens[1].session.to_string());
    let failed_id = CommandId::new(
        slot["predecessorCommand"]
            .as_str()
            .expect("failed brief identity"),
    )
    .expect("failed command id");
    let history = fixture
        .ledger
        .history(odin_domain::huginn::HistoryQuery {
            session_id: opens[0].session,
            after: odin_domain::huginn::EventSeq::new(0),
            limit: std::num::NonZeroU16::new(64).expect("history bound"),
        })
        .await
        .expect("failed successor history");
    assert_eq!(history.next_after, history.head, "complete fixture history");
    let failed_outcomes = history
        .events
        .iter()
        .filter(|event| {
            matches!(
                &event.body,
                LiveEventBody::ControlCompleted(CommandOutcome::Failed { command_id, error })
                    if command_id == &failed_id && error.message.contains("fixture_prompt_rejected")
            )
        })
        .count();
    assert_eq!(
        failed_outcomes, 1,
        "the first brief settled Failed exactly once"
    );
    let applied_command: LiveCommand = serde_json::from_value(slot["briefCommand"].clone())
        .expect("the retained successful brief command");
    assert_ne!(applied_command.command_id, failed_id);
    assert_eq!(applied_command.session_id, opens[1].session);
    let applied = fixture
        .ledger
        .command(&applied_command)
        .await
        .expect("successor admission readable")
        .expect("successor admission durable");
    assert!(matches!(
        applied.receipt,
        odin_domain::huginn::CommandReceipt::Duplicate { prior_outcome: Some(outcome), .. }
            if matches!(outcome.as_ref(), CommandOutcome::Applied { command_id }
                if command_id == &applied_command.command_id)
    ));
    fixture
        .root
        .initialize()
        .await
        .expect("an opened vehicle re-initializes idempotently");
    assert_eq!(
        fixture.probe.prompts().len(),
        2,
        "neither brief is ever replayed"
    );
}

/// Transport loss after admission is NOT a definitive failure: startup
/// refuses with the pending identity intact instead of minting a replacement.
#[tokio::test]
async fn ambiguous_admitted_brief_keeps_its_pending_identity() {
    let fixture = stage_row(true, None, None).await;
    fixture
        .probe
        .fail_prompt_transport
        .store(true, Ordering::SeqCst);
    let error = fixture
        .root
        .initialize()
        .await
        .expect_err("transport ambiguity must not claim a failed or applied brief");
    assert!(error
        .to_string()
        .contains("fixture_prompt_transport_failed"));
    let opens = fixture.probe.opens();
    assert_eq!(opens.len(), 1, "no replacement for an unresolved admission");
    assert_eq!(
        fixture.probe.prompts().len(),
        1,
        "no replay of the admitted brief"
    );
    assert!(!is_terminal(&fixture, opens[0].session).await);
    let slot = recorded_rollover(&fixture);
    assert_eq!(slot["phase"], "pending");
    assert_eq!(slot["predecessorSession"], fixture.session.to_string());
    assert_eq!(slot["successorSession"], opens[0].session.to_string());
    let command: LiveCommand = serde_json::from_value(slot["briefCommand"].clone())
        .expect("the pending brief retains its exact command");
    assert_eq!(command.session_id, opens[0].session);
    let entry = fixture
        .ledger
        .command(&command)
        .await
        .expect("pending admission readable")
        .expect("pending admission durable");
    assert_eq!(
        entry.command, command,
        "the exact admission is never retargeted"
    );
    assert!(matches!(
        entry.receipt,
        odin_domain::huginn::CommandReceipt::Duplicate {
            prior_outcome: None,
            ..
        }
    ));
}
