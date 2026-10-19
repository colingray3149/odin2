//! The declared conversation seams and their production adapters: the
//! paired owner surface, the authority, plane, and egress edges, the
//! kernel approval surface, and the daemon-composition config.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use odin_domain::huginn::{
    CommandReceipt, EventSeq, HistoryPage, HistoryQuery, LiveCommand, LiveError, LiveSessionId,
    LiveSessionSummary, ModelName, OpenSessionRequest, ProviderName, SessionListPage,
    SessionListQuery, SessionSubscription, SubscribeRequest,
};
use odin_domain::{CommandId, LaneId, NodeId, ProjectId};
use odin_ledger::Ledger;
use odin_omp::live::service::OmpLiveService;
use odin_omp::live::supervisor::LiveSeatBinding;
use time::OffsetDateTime;

use crate::egress::{DeliveryCheckpoint, EgressError, ReplyChunks};
use crate::natural::OwnerDecision;
use crate::runtime::{
    AuthenticatedOwnerMessage, DecisionRefusal, DeliveredApproval, HermesRuntime,
};

/// The one paired owner surface. There is no unpaired fallback.
#[derive(Clone, Debug)]
pub struct OwnerSurface {
    /// The paired owner's transport identity.
    pub owner_user_id: String,
    /// The paired DM channel the questions are delivered on.
    pub channel_id: String,
    /// The durable acceptance actor recording the owner's plan acceptance
    /// provenance (for example `discord-owner:<id>`).
    pub actor: String,
}

/// Verifies published authority for the session before open, recovery or continued use;
/// revoked or unusable authority is not reissued here.
#[async_trait]
pub trait ConversationAuthority: Send + Sync {
    /// Returns the token's frozen publication revision and the current snapshot revision
    /// so the caller can decide whether the session needs a successor.
    async fn ensure(
        &self,
        command_id: &CommandId,
        session_id: LiveSessionId,
    ) -> Result<EnsuredGeneration, String>;

    /// True while the host cannot yet serve a session at the current pin
    /// (odind's idle reload after a runtime publication is still pending):
    /// a successor opened now could never run its first turn, so a lagging
    /// but healthy vehicle keeps serving on its retained publication and
    /// rolls after the reload. Hosts without such a gate never defer.
    fn rollover_deferred(&self) -> bool {
        false
    }

    /// The successor transition's trouble, for the host's incident desk:
    /// every caller of the transition (startup, a turn, a decision, a
    /// queued wake) reports through here. Hosts without a desk ignore it.
    fn successor_trouble(&self, _conversation_id: &str, _trouble: SuccessorTrouble) {}
}

/// What the successor transition tells the host's incident desk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuccessorTrouble {
    /// `attempts` successors ended before serving; the next is minted no
    /// sooner than `retry_at_unix_ms`.
    Backoff {
        attempts: u32,
        retry_at_unix_ms: u64,
    },
    /// The durable cap stopped minting under this build; `newly` is the
    /// transition itself, later reports restate it.
    Exhausted { attempts: u32, newly: bool },
    /// A successor opened and served: the trouble is over.
    Recovered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnsuredGeneration {
    /// The ensured token's own served_revision claim.
    pub bound: u64,
    /// The pinned snapshot revision this ensure call resolved.
    pub current: u64,
    /// Composition digests for both publications; `None` compares revisions alone.
    pub composition: Option<CompositionPair>,
}

/// The composition digests of a vehicle's bound and the current publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionPair {
    pub bound: odin_registry::CompositionDigest,
    pub current: odin_registry::CompositionDigest,
}

impl EnsuredGeneration {
    /// Revision changes need a successor unless matching composition digests show
    /// the vehicle is unchanged, as with publication of only live-read objects.
    pub fn lags(&self) -> bool {
        self.bound != self.current && self.kept_composition().is_none()
    }

    /// The digest the vehicle keeps when the pin advanced past its bound
    /// without changing its composition; `None` when the revisions agree or
    /// the composition changed or is unproven.
    pub fn kept_composition(&self) -> Option<odin_registry::CompositionDigest> {
        match self.composition {
            Some(pair) if self.bound != self.current && pair.bound == pair.current => {
                Some(pair.current)
            }
            _ => None,
        }
    }
}

#[async_trait]
pub trait ConversationPlane: Send + Sync {
    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError>;
    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError>;
    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError>;
    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError>;
    /// Waits until the durable session feed has an event after `after`.
    /// Callers still re-read history; the stream is notification, not truth.
    async fn wait_for_history(
        &self,
        session_id: LiveSessionId,
        after: EventSeq,
    ) -> Result<(), LiveError>;
    /// Recovers the root's own child session IN PLACE: same session id,
    /// epoch bump, durable transcript resumed. A truthfully ended session
    /// refuses typed before any effect.
    async fn recover_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError>;
    /// The authoritative journal lookup: whether the live ledger ever
    /// ADMITTED this exact command.
    async fn command_entry(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<odin_omp::live::ledger::CommandJournalEntry>, LiveError>;
    /// Whether the durable session manifest exists (the open was ever
    /// admitted), independent of any live actor.
    async fn session_manifest_present(&self, session_id: LiveSessionId) -> Result<bool, LiveError>;
}

/// The governed reply sink to the paired owner's channel. A reply longer
/// than the per-message bound travels as consecutive bounded chunks; the
/// returned [`ReplyChunks`] own every physical message, and their `anchor`
/// — the first — is the stable identity ordering, durable receipts, and
/// mirror reservations use across edits.
pub trait ConversationEgress: Send + Sync {
    fn deliver(
        &self,
        content: &str,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError>;

    /// Shows the owner that a reply is being written.
    fn typing(&self) -> Result<(), String>;

    /// One owner turn was answered: the seat may learn from it, in the
    /// background.
    fn turn_answered(&self, _exchange: crate::runtime::review::Exchange) {}
}

/// Whether a settled kernel decision woke the conversation approved or
/// denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelDecisionOutcome {
    Approved,
    Denied,
    /// The decision did not settle; nothing was authorized.
    NotSettled,
}

/// Discovers approvals within the conversation and decides their delivered request and revision.
#[async_trait]
pub trait KernelApprovals: Send + Sync {
    /// Pending approvals with a delivery record for this owner and channel.
    async fn delivered_pending(
        &self,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, DecisionRefusal>;
    /// Sends session questions not yet confirmed at their current revision. Failed sends
    /// remain pending; returns newly delivered, still-decidable questions.
    async fn deliver_session_questions(
        &self,
        session: &LiveSessionId,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, String>;
    /// Decides one delivered approval at the exact delivered revision.
    /// `Ok(None)` means nothing was consumable for this message; an `Err`
    /// is the typed refusal (nothing authorized, nothing recorded).
    async fn decide_delivered(
        &self,
        message: &AuthenticatedOwnerMessage,
        approval: &DeliveredApproval,
        decision: OwnerDecision,
        now: OffsetDateTime,
    ) -> Result<Option<KernelDecisionOutcome>, DecisionRefusal>;
    /// The durable authority row, including consumed and terminal outcomes.
    async fn approval_status(
        &self,
        approval_id: &str,
    ) -> Result<Option<odin_domain::ApprovalStatus>, String>;
    /// Moves the conversation's open approvals (and the daemon's coding
    /// review evidence) from a superseded vehicle session onto its
    /// successor; returns how many approvals moved.
    async fn follow_vehicle(
        &self,
        predecessor: &LiveSessionId,
        successor: &LiveSessionId,
    ) -> Result<usize, String> {
        let _ = (predecessor, successor);
        Ok(0)
    }
    /// The exact call an approved request re-issues — its tool and retry
    /// arguments, from the durable commands journal — so the retry never
    /// depends on the model still holding the original call.
    async fn approved_call(&self, approval_id: &str) -> Option<(String, serde_json::Value)> {
        let _ = approval_id;
        None
    }
}

/// Uses the runtime's delivery records and the shared ledger for decisions.
/// The weak runtime reference avoids a cycle with the route it owns.
pub struct DaemonKernelApprovals {
    pub runtime: std::sync::Weak<HermesRuntime>,
    pub ledger: Arc<parking_lot::Mutex<Ledger>>,
    /// The daemon's delegation links: approvals a delegated child requests
    /// reach the owner through the parent conversation, since only the
    /// owner can decide them. `None` relays the vehicle's own only.
    pub delegation_links: Option<odin_omp::host_tools::delegation::DelegationLinkLedger>,
}

impl DaemonKernelApprovals {
    fn runtime(&self) -> Result<Arc<HermesRuntime>, String> {
        self.runtime
            .upgrade()
            .ok_or_else(|| "the hermes runtime is gone".to_owned())
    }

    /// The still-`requested` approvals whose scope targets this vehicle
    /// session or one of its delegated children, by durable ledger row.
    /// Requested approvals of this vehicle and of the workers it delegated,
    /// each marked whether it came from a delegated worker.
    fn scoped_requested(&self, session: &LiveSessionId) -> Vec<(String, bool)> {
        let mut sessions = vec![*session];
        if let Some(links) = &self.delegation_links {
            match odin_domain::SessionId::new(session.to_string())
                .map_err(|error| error.to_string())
                .and_then(|parent| links.children_of(&parent))
            {
                Ok(children) => sessions.extend(children.into_iter().map(|link| link.child)),
                Err(error) => {
                    tracing::error!(error = %error, "conversation route could not list delegated children: {error}")
                }
            }
        }
        let guard = self.ledger.lock();
        let mut requested = Vec::new();
        for (index, session) in sessions.into_iter().enumerate() {
            match guard.requested_approvals_for_target("run", &format!("run:live:{session}")) {
                Ok(approvals) => requested.extend(
                    approvals
                        .into_iter()
                        .map(|approval| (approval.approval_id.to_string(), index > 0)),
                ),
                Err(error) => {
                    tracing::error!(error = %error, "conversation route could not read scoped approvals: {error}")
                }
            }
        }
        requested
    }
}

#[async_trait]
impl KernelApprovals for DaemonKernelApprovals {
    async fn delivered_pending(
        &self,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, DecisionRefusal> {
        self.runtime()
            .map_err(DecisionRefusal::Evidence)?
            .delivered_pending_approvals(&self.ledger, channel_id, owner_user_id, now)
    }

    async fn deliver_session_questions(
        &self,
        session: &LiveSessionId,
        channel_id: &str,
        owner_user_id: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<DeliveredApproval>, String> {
        let runtime = self.runtime()?;
        let vehicle = format!("run:live:{session}");
        // Do not repost the current revision; return only questions raised by this poll.
        let asked: std::collections::BTreeSet<String> = runtime
            .delivered_pending_approvals(&self.ledger, channel_id, owner_user_id, now)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|approval| approval.approval_id.to_string())
            .collect();
        // Repost successor revisions for valid replies, but do not treat them as this turn's new questions.
        let ever = runtime
            .ever_delivered_approvals(&self.ledger, channel_id, owner_user_id)
            .map_err(|error| error.to_string())?;
        for (approval_id, delegated) in self.scoped_requested(session) {
            if asked.contains(&approval_id) {
                continue;
            }
            let Ok(approval_id) = odin_domain::ApprovalId::new(&approval_id) else {
                continue;
            };
            if let Err(error) = runtime.deliver_approval_question(
                &self.ledger,
                &approval_id,
                channel_id,
                owner_user_id,
                now,
                delegated.then_some(vehicle.as_str()),
            ) {
                // A failed send stays pending: the next poll retries and
                // nothing was authorized by an undelivered question.
                tracing::error!(
                    approval = %approval_id,
                    error = %error,
                    "conversation route could not deliver approval question {approval_id}: {error}"
                );
            }
        }
        Ok(runtime
            .delivered_pending_approvals(&self.ledger, channel_id, owner_user_id, now)
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|approval| !ever.contains(approval.approval_id.as_str()))
            .collect())
    }

    async fn decide_delivered(
        &self,
        message: &AuthenticatedOwnerMessage,
        approval: &DeliveredApproval,
        decision: OwnerDecision,
        now: OffsetDateTime,
    ) -> Result<Option<KernelDecisionOutcome>, DecisionRefusal> {
        let outcome = self
            .runtime()
            .map_err(DecisionRefusal::Evidence)?
            .decide_delivered_approval(
                &self.ledger,
                message,
                &approval.approval_id,
                approval.revision,
                decision,
                now,
            )?;
        Ok(match outcome {
            odin_kernel::DecisionOutcome::Approved(_) => Some(KernelDecisionOutcome::Approved),
            odin_kernel::DecisionOutcome::Denied(_) => Some(KernelDecisionOutcome::Denied),
            odin_kernel::DecisionOutcome::Redirect(_) => Some(KernelDecisionOutcome::NotSettled),
        })
    }

    async fn approval_status(
        &self,
        approval_id: &str,
    ) -> Result<Option<odin_domain::ApprovalStatus>, String> {
        let approval_id = odin_domain::ApprovalId::new(approval_id)
            .map_err(|error| format!("approval identity invalid: {error}"))?;
        let guard = self.ledger.lock();
        let approval = guard
            .approval(&approval_id)
            .map_err(|error| format!("could not read the approval row: {error}"))?;
        Ok(approval.map(|approval| approval.status))
    }

    async fn follow_vehicle(
        &self,
        predecessor: &LiveSessionId,
        successor: &LiveSessionId,
    ) -> Result<usize, String> {
        let moved = self
            .ledger
            .lock()
            .follow_approval_target(
                "run",
                &format!("run:live:{predecessor}"),
                &format!("run:live:{successor}"),
                OffsetDateTime::now_utc(),
            )
            .map_err(|error| format!("open approvals could not follow the vehicle: {error}"))?;
        for approval in &moved {
            tracing::info!(
                approval = %approval,
                session = %predecessor,
                successor = %successor,
                "odin-hermes: approval {approval} follows the conversation from {predecessor} to {successor}"
            );
        }
        // The coding review lane's exact test and review evidence follows
        // the same trusted transition, outside the approval-ledger lock.
        self.runtime()?
            .carry_review_evidence(predecessor, successor)?;
        Ok(moved.len())
    }

    async fn approved_call(&self, approval_id: &str) -> Option<(String, serde_json::Value)> {
        let runtime = self.runtime.upgrade()?;
        let approval_id = odin_domain::ApprovalId::new(approval_id).ok()?;
        let guard = self.ledger.lock();
        let approval = guard.approval(&approval_id).ok()??;
        let (_, retry) = crate::runtime::authority::durable_retry_arguments(&guard, &approval)?;
        Some((runtime.tool_name_of(&approval.scope.capability_id)?, retry))
    }
}

/// The bounded live-plane seam served by the daemon's real live service:
/// recovery is the plane's reclaim surface; the journal lookup is the
/// authoritative admission fact.
#[async_trait]
impl ConversationPlane for OmpLiveService {
    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        odin_domain::huginn::OmpLivePlane::sessions(self, query).await
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        odin_domain::huginn::OmpLivePlane::open_session(self, request).await
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        odin_domain::huginn::OmpLivePlane::command(self, command).await
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        odin_domain::huginn::OmpLivePlane::history(self, query).await
    }

    async fn wait_for_history(
        &self,
        session_id: LiveSessionId,
        after: EventSeq,
    ) -> Result<(), LiveError> {
        let mut stream = odin_domain::huginn::OmpLivePlane::subscribe(
            self,
            SubscribeRequest {
                subscriptions: vec![SessionSubscription {
                    session_id,
                    event_after: after,
                    terminal_after: None,
                }],
            },
        )
        .await?;
        match stream.next().await {
            Some(Ok(_)) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(LiveError::Unavailable {
                code: "conversation_history_subscription_closed".to_owned(),
            }),
        }
    }

    async fn recover_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        odin_domain::huginn::OmpLivePlane::reclaim_session(self, session_id).await
    }

    async fn command_entry(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<odin_omp::live::ledger::CommandJournalEntry>, LiveError> {
        OmpLiveService::command_entry(self, command).await
    }

    async fn session_manifest_present(&self, session_id: LiveSessionId) -> Result<bool, LiveError> {
        OmpLiveService::session_manifest_present(self, session_id).await
    }
}

/// The cycle-free egress edge: the runtime owns the route, so the route
/// holds the runtime WEAKLY and upgrades per call. A gone runtime is a
/// typed unavailable error, never a leak.
impl ConversationEgress for std::sync::Weak<HermesRuntime> {
    fn deliver(
        &self,
        content: &str,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError> {
        self.upgrade()
            .ok_or(EgressError::InvalidState("the hermes runtime is gone"))?
            .deliver_checkpointed(content, checkpoint)
    }

    fn typing(&self) -> Result<(), String> {
        self.upgrade()
            .ok_or_else(|| "the hermes runtime is gone".to_owned())?
            .typing()
    }

    fn turn_answered(&self, exchange: crate::runtime::review::Exchange) {
        if let Some(runtime) = self.upgrade() {
            runtime.review_after(exchange);
        }
    }
}

/// Everything the root needs, exactly declared.
pub struct ConversationRootConfig {
    /// The seat's exact live binding from the strict composition helper.
    pub binding: LiveSeatBinding,
    /// The declared served project.
    pub project: ProjectId,
    /// The declared session lane the vehicle run is admitted under.
    pub lane: LaneId,
    /// The chosen declared launch provider (verified against the binding).
    pub provider: ProviderName,
    /// The chosen declared launch model (verified against the binding).
    pub model: ModelName,
    /// The canonical serving local node (verified against the binding).
    pub target_node: NodeId,
    /// The paired owner surface — no unpaired fallback.
    pub owner: OwnerSurface,
    /// The declared bound for waiting on a settled answer. A genuine
    /// owner decision wait never consumes it.
    pub answer_bound: StdDuration,
    /// The history poll cadence while waiting.
    pub poll_interval: StdDuration,
    pub plane: Arc<dyn ConversationPlane>,
    pub authority: Arc<dyn ConversationAuthority>,
    pub egress: Arc<dyn ConversationEgress>,
    pub approvals: Arc<dyn KernelApprovals>,
    /// Shared session-state ledger used for plan acceptance.
    pub ledger_path: PathBuf,
    /// The durable root record file.
    pub state_path: PathBuf,
    /// The seat's declared `[live.rollover]` policy: bounds the successor
    /// brief every vehicle rollover carries.
    pub rollover: odin_omp::live::rollover::RolloverPolicy,
    /// The owner's clock: when present every prompt opens with his local
    /// time, so the seat always knows "now" without a tool call.
    pub clock: Option<crate::schedule::OwnerClock>,
    /// The daemon's delegation links: the successor brief carries the
    /// predecessor's delegated children and their answers from these.
    pub delegation_links: Option<odin_omp::host_tools::delegation::DelegationLinkLedger>,
}
