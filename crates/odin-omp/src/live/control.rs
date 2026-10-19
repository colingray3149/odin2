use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use odin_brain::context::{ContextTokenizer, PINNED_TOKENIZER_ID};
use odin_domain::huginn::{
    AbortScope, ApprovalDecision, LiveCommandBody, LiveContentBlock, LiveError, LiveMessage,
    LiveSessionState, ModelName, PermissionDecision, PermissionRequestId, ProviderName,
};
use odin_domain::knowledge::ids::TokenizerId;
use odin_domain::{ApprovalId, NodeId, SeatId};
use serde_json::Value;

use crate::bridge::{OmpBridge, Prompt, StreamingBehavior};

#[derive(Clone, Debug)]
pub struct ControlEffect {
    pub state: Option<LiveSessionState>,
    pub provider: Option<ProviderName>,
    pub model: Option<ModelName>,
    pub target_node: Option<NodeId>,
    pub reclaim_epoch: bool,
    pub terminate: bool,
    /// The epoch the bridge published for this effect, when the backend
    /// owns the reclaim (the typed rollover); the actor verifies its own
    /// journal advance against it.
    pub epoch: Option<i64>,
}

impl ControlEffect {
    fn unchanged() -> Self {
        Self {
            state: None,
            provider: None,
            model: None,
            target_node: None,
            reclaim_epoch: false,
            terminate: false,
            epoch: None,
        }
    }
}

#[async_trait]
pub trait LiveControlBackend: Send + Sync {
    async fn prompt(&self, message: &LiveMessage) -> Result<(), LiveError>;
    async fn follow_up(&self, message: &LiveMessage) -> Result<(), LiveError>;
    /// Opt in only when dispatch preserves command identity and cannot repeat
    /// external effects on replay, including after an interrupted dispatch.
    /// The default prompt/follow-up adapter is first-dispatch only: an
    /// incomplete admission must remain indeterminate for these backends.
    fn supports_identity_safe_dispatch(&self) -> bool {
        false
    }

    async fn message_outcome(
        &self,
        _command_id: &odin_domain::CommandId,
    ) -> Result<Option<bool>, LiveError> {
        Ok(None)
    }
    async fn dispatch_message(
        &self,
        _command_id: &odin_domain::CommandId,
        message: &LiveMessage,
        follow_up: bool,
    ) -> Result<bool, LiveError> {
        if follow_up {
            self.follow_up(message).await?;
        } else {
            self.prompt(message).await?;
        }
        Ok(true)
    }
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError>;
    async fn pause(&self) -> Result<(), LiveError>;
    async fn resume(&self) -> Result<(), LiveError>;
    async fn checkpoint(&self) -> Result<(), LiveError>;
    async fn restart(&self) -> Result<(), LiveError>;

    /// A typed context-refusal rollover of this session: planned
    /// fresh-context respawn (same session identity, epoch + 1, a NEW empty
    /// conversation) carrying ONE journaled continuity brief, with the
    /// journaled model selection — `selected_model`, when it differs from
    /// the launch pair — re-asserted after the respawn and BEFORE the
    /// reinjection turn. `refusal_event` is the provider error event the
    /// rollover answers (journaled evidence). Only the bridge-backed
    /// session control implements it; a rollover needs the session's
    /// declared rollover configuration.
    async fn rollover_fresh(
        &self,
        refusal_event: u64,
        selected_model: Option<(&ProviderName, &ModelName)>,
    ) -> Result<i64, LiveError> {
        let _ = (refusal_event, selected_model);
        Err(LiveError::InvalidRequest {
            code: "rollover_unsupported".to_owned(),
            message: "this session control cannot roll a fresh context".to_owned(),
        })
    }
    async fn rehome(&self, target_node: &NodeId) -> Result<(), LiveError>;
    async fn set_model(&self, provider: &ProviderName, model: &ModelName) -> Result<(), LiveError>;
    async fn abort_turn(&self) -> Result<(), LiveError>;
    async fn abort_session(&self) -> Result<(), LiveError>;
    async fn shutdown(&self) -> Result<(), LiveError>;
    async fn decide_permission(
        &self,
        request_id: &PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), LiveError>;
    async fn decide_approval(
        &self,
        approval_id: &ApprovalId,
        expected_revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError>;

    /// Readiness is independent of whether the child has exited.
    async fn bridge_ready(&self) -> bool;

    /// Whether child exit or teardown completed; defaults to occupying capacity.
    async fn process_exited(&self) -> bool {
        false
    }
}

#[async_trait]
pub trait LiveControlHooks: Send + Sync {
    async fn pause(&self) -> Result<(), LiveError>;
    async fn resume(&self) -> Result<(), LiveError>;
    async fn rehome(&self, target_node: &NodeId) -> Result<(), LiveError>;
    async fn decide_approval(
        &self,
        approval_id: &ApprovalId,
        expected_revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError>;
}

/// Host-owned per-turn untrusted-memory source of one workload session.
/// Implementations retrieve the session profile's declared namespace facts
/// fresh at every dispatch from the bound seat's own brain service. A
/// retrieval failure is a typed error — a stale or silently omitted facts
/// block is never rendered, and the rendered data is quoted reference
/// material, never instructions or authority.
pub trait WorkloadTurnSource: Send + Sync {
    fn turn_facts(&self, seat: &SeatId, profile: &str) -> Result<String, LiveError>;
}

/// The declared context-counting lane of one session: the admitted launch
/// identity, the declared window, the compiler-resolved effective output
/// reserve, and the declared context tokenizer identity. Staged verbatim
/// into the child's `ODIN_CONTEXT_BUDGET` as
/// `provider|model|window|reserve|tokenizer` and consumed by the trusted
/// extension guard, the host dispatch guard, and the per-turn brain
/// compilation — one declaration, one counting policy everywhere.
#[derive(Clone, Debug)]
pub struct LaneContextBudget {
    pub provider: String,
    pub model: String,
    pub window: u64,
    /// The EFFECTIVE reserved output: what the compiler resolved from the
    /// authored slice/seat declaration against this window, so the host
    /// guard, the launch staging, and the extension's output cap all speak
    /// the same number the compile actually budgeted against.
    pub reserve: u64,
    pub tokenizer: TokenizerId,
}

impl LaneContextBudget {
    /// The exact byte-policy identity: whole-request text counted as UTF-8
    /// bytes (one token per byte). Any other declared identity is a native
    /// counting lane.
    pub fn byte_policy(&self) -> bool {
        self.tokenizer.as_str() == PINNED_TOKENIZER_ID
    }

    /// The staged declaration the trusted extension parses — the one
    /// producer-side serialization of this lane's contract.
    pub fn stage(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.provider, self.model, self.window, self.reserve, self.tokenizer
        )
    }

    /// The context counter this lane's declared identity names. Cheap to
    /// construct; the underlying engine loads once per process.
    pub fn counter(&self) -> Result<ContextTokenizer, LiveError> {
        ContextTokenizer::for_id(&self.tokenizer).map_err(|error| LiveError::Unavailable {
            code: format!("lane_context_tokenizer: {error}"),
        })
    }
}

/// Every declared context budget of one session: one lane per model the
/// session may run (its seat's declared launch options that declare a
/// window). The budget in force is always the one of the model the session
/// is running NOW, so a declared model switch keeps the guard, and a switch
/// to a model without a declared window is refused before it happens.
/// Staged into `ODIN_CONTEXT_BUDGET` as `;`-joined lane stages.
#[derive(Clone, Debug)]
pub struct LaneContextBudgets {
    lanes: Vec<LaneContextBudget>,
}

impl LaneContextBudgets {
    /// The declared set, or `None` when no lane declares a window.
    pub fn new(lanes: Vec<LaneContextBudget>) -> Option<Self> {
        (!lanes.is_empty()).then_some(Self { lanes })
    }

    /// The declared budget of one exact model identity.
    pub fn for_model(&self, provider: &str, model: &str) -> Option<&LaneContextBudget> {
        self.lanes
            .iter()
            .find(|lane| lane.provider == provider && lane.model == model)
    }

    /// The staged declaration the trusted extension parses.
    pub fn stage(&self) -> String {
        self.lanes
            .iter()
            .map(LaneContextBudget::stage)
            .collect::<Vec<_>>()
            .join(";")
    }
}

/// Validated lane identity and context estimate for compiler planning only.
/// Final structured-fit and whole-request checks enforce the actual payload size.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedLaneState {
    pub context_usage_tokens: u64,
}

/// The native tokenizer family the declared identity counts with, per the
/// pinned harness's catalog resolution (`Model.tokenizer`).
fn declared_family(tokenizer: &TokenizerId) -> Result<&'static str, LiveError> {
    match tokenizer.as_str() {
        odin_brain::context::QWEN3_TOKENIZER_ID => Ok("qwen3"),
        PINNED_TOKENIZER_ID => Err(LiveError::InvalidRequest {
            code: "lane_context_state".to_owned(),
            message: "the byte-counting lane measures whole-request bytes itself and \
                      never consumes harness snapshots; requested one anyway"
                .to_owned(),
        }),
        other => Err(LiveError::InvalidRequest {
            code: "lane_context_state".to_owned(),
            message: format!("declared tokenizer identity {other} has no native family"),
        }),
    }
}

/// Validates provider, model, window, and tokenizer before using context usage
/// for planning. Missing counts fail rather than becoming zero; dispatch-size
/// enforcement remains with the final structured-fit and whole-request checks.
pub fn verify_lane_state(
    budget: &LaneContextBudget,
    state: &Value,
) -> Result<VerifiedLaneState, LiveError> {
    let family = declared_family(&budget.tokenizer)?;
    let mismatch = |detail: String| LiveError::Unavailable {
        code: format!("lane_context_state: {detail}"),
    };
    let model = state
        .get("model")
        .filter(|model| model.is_object())
        .ok_or_else(|| mismatch("the harness state carries no model object".to_owned()))?;
    let provider = model.get("provider").and_then(Value::as_str);
    if provider != Some(budget.provider.as_str()) {
        return Err(mismatch(format!(
            "harness model provider {provider:?} does not match the declared {}",
            budget.provider
        )));
    }
    let id = model.get("id").and_then(Value::as_str);
    if id != Some(budget.model.as_str()) {
        return Err(mismatch(format!(
            "harness model id {id:?} does not match the declared {}",
            budget.model
        )));
    }
    let window = model.get("contextWindow").and_then(Value::as_u64);
    if window != Some(budget.window) {
        return Err(mismatch(format!(
            "harness model context window {window:?} does not match the declared {}",
            budget.window
        )));
    }
    let tokenizer = model.get("tokenizer").and_then(Value::as_str);
    if tokenizer != Some(family) {
        return Err(mismatch(format!(
            "harness model tokenizer family {tokenizer:?} does not match the declared \
             {family} counting lane"
        )));
    }
    let usage = state.get("contextUsage").ok_or_else(|| {
        mismatch(
            "the harness state carries no contextUsage; the native lane refuses \
                  to plan on an unmeasured snapshot"
                .to_owned(),
        )
    })?;
    let tokens = usage
        .get("tokens")
        .and_then(Value::as_u64)
        .ok_or_else(|| mismatch("harness contextUsage carries no usable token count".to_owned()))?;
    Ok(VerifiedLaneState {
        context_usage_tokens: tokens,
    })
}

/// Byte lanes enforce measured context plus input and reserve against the window.
/// Native lanes require a verified planning estimate and reject unsupported media;
/// their final extension checks enforce size on the assembled request, not this estimate.
pub fn lane_context_decision(
    budget: &LaneContextBudget,
    state: Option<&VerifiedLaneState>,
    watermark: Option<u64>,
    incoming_tokens: u64,
    image_tokens: u64,
) -> Result<(), LiveError> {
    if budget.byte_policy() {
        let Some(watermark) = watermark else {
            // No settled turn yet: the byte lane has no measured
            // accumulated context, and inventing one is forbidden. The
            // extension's complete-request byte count remains the guard.
            return Ok(());
        };
        let required = watermark
            .saturating_add(incoming_tokens)
            .saturating_add(image_tokens)
            .saturating_add(budget.reserve);
        if required <= budget.window {
            return Ok(());
        }
        return Err(LiveError::Unavailable {
            code: format!(
                "lane_context_cannot_fit: the measured accumulated context \
                 ({watermark} UTF-8 byte tokens) plus this turn's rendered input \
                 ({incoming_tokens} tokens) plus the reserved output ({}) require \
                 {required} tokens, exceeding the declared lane window of {}; compact \
                 or restart the session and retry",
                budget.reserve, budget.window
            ),
        });
    }
    // Native lane: snapshot verification is mandatory (never planned as
    // zero), media is outside any declared text policy, and the estimate
    // alone never refuses — the final structured fit and the extension
    // guard own the window.
    state.ok_or_else(|| LiveError::Unavailable {
        code: "lane_context_state: the declared native context lane requires a \
               verified harness snapshot before every dispatch"
            .to_owned(),
    })?;
    if image_tokens > 0 {
        return Err(LiveError::Unavailable {
            code: "lane_context_media: the declared native text counting lane \
                   cannot bound image attachments; the turn is refused before \
                   dispatch"
                .to_owned(),
        });
    }
    Ok(())
}

/// Host-owned per-turn memory of one session: the seat's distilled core
/// rides the system prompt from launch, so a turn carries at most the
/// prefetch — a few confident matches for its text, rendered as untrusted
/// reference — and nothing when the gate is not confident.
pub trait BrainTurnContext: Send + Sync {
    /// `epoch_start`: the first turn of the session or of a compaction
    /// epoch, which carries the profile's full brain context; ordinary turns
    /// carry only the profile's per-turn tail, if it declares one.
    fn prefetch(&self, text: &str, epoch_start: bool) -> Result<Option<String>, LiveError>;
}

pub struct BridgeControl {
    bridge: Arc<OmpBridge>,
    hooks: Arc<dyn LiveControlHooks>,
    workload_turns: Option<(SeatId, String, Arc<dyn WorkloadTurnSource>)>,
    brain_turns: Option<Arc<dyn BrainTurnContext>>,
    /// The session's declared context budgets, one per model it may run.
    /// `Some` arms the dispatch guard and the verified-snapshot overhead
    /// flow against the budget of the model running now; `None` — seats
    /// without a declared brain context policy, or a launch model without a
    /// declared window — keeps dispatch byte-identical.
    lane_context_budgets: Option<LaneContextBudgets>,
    /// The launch model and the model the session is running now
    /// (`(provider, model)`); a restart respawns on the launch model.
    launch_model: (String, String),
    current_model: RwLock<(String, String)>,
    /// The bridge context epoch whose turn last carried the epoch's
    /// workload facts and brain context; `u64::MAX` before the first turn.
    injected_epoch: std::sync::atomic::AtomicU64,
}

impl BridgeControl {
    pub fn new(bridge: Arc<OmpBridge>, hooks: Arc<dyn LiveControlHooks>) -> Self {
        Self {
            bridge,
            hooks,
            workload_turns: None,
            brain_turns: None,
            lane_context_budgets: None,
            launch_model: (String::new(), String::new()),
            current_model: RwLock::new((String::new(), String::new())),
            injected_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Binds the session's declared context budgets and its launch model.
    pub fn with_lane_context_budgets(
        mut self,
        budgets: Option<LaneContextBudgets>,
        provider: &ProviderName,
        model: &ModelName,
    ) -> Self {
        self.lane_context_budgets = budgets;
        self.launch_model = (provider.as_str().to_owned(), model.as_str().to_owned());
        self.current_model = RwLock::new(self.launch_model.clone());
        self
    }

    /// The declared budget of the model the session is running now. A
    /// session whose declared set lacks its current model refuses typed:
    /// the switch guard makes that unreachable, so it is never guessed.
    fn current_lane(&self) -> Result<Option<LaneContextBudget>, LiveError> {
        let Some(budgets) = &self.lane_context_budgets else {
            return Ok(None);
        };
        let current = self
            .current_model
            .read()
            .map_err(|_| LiveError::Unavailable {
                code: "lane_context_budget: current model lock poisoned".to_owned(),
            })?;
        budgets
            .for_model(&current.0, &current.1)
            .cloned()
            .map(Some)
            .ok_or_else(|| LiveError::Unavailable {
                code: format!(
                    "lane_context_budget: no context window is declared for {}/{}",
                    current.0, current.1
                ),
            })
    }

    fn set_current_model(&self, model: (String, String)) -> Result<(), LiveError> {
        *self
            .current_model
            .write()
            .map_err(|_| LiveError::Unavailable {
                code: "lane_context_budget: current model lock poisoned".to_owned(),
            })? = model;
        Ok(())
    }

    /// Binds the per-turn workload facts source of this session: the bound
    /// seat, the published profile id, and the host-owned retrieval source.
    /// `None` — every seat conversation session — leaves prompts
    /// byte-identical.
    pub fn with_workload_turns_source(
        mut self,
        workload_turns: Option<(SeatId, String, Arc<dyn WorkloadTurnSource>)>,
    ) -> Self {
        self.workload_turns = workload_turns;
        self
    }

    /// Binds the per-turn brain context source of this session. `None` —
    /// seats without a declared brain `[context]` policy — keeps prompts
    /// byte-identical.
    pub fn with_brain_turn_source(
        mut self,
        brain_turns: Option<Arc<dyn BrainTurnContext>>,
    ) -> Self {
        self.brain_turns = brain_turns;
        self
    }

    /// Fetches fresh native-lane identity and planning usage; byte lanes use measured bytes.
    async fn verified_lane_state(
        &self,
        lane: Option<&LaneContextBudget>,
    ) -> Result<Option<VerifiedLaneState>, LiveError> {
        let Some(budget) = lane else {
            return Ok(None);
        };
        if budget.byte_policy() {
            return Ok(None);
        }
        let state = self
            .bridge
            .state()
            .await
            .map_err(|error| LiveError::Unavailable {
                code: format!("lane_context_state: the harness snapshot is unavailable: {error}"),
            })?;
        verify_lane_state(budget, &state).map(Some)
    }

    /// Builds one outgoing dispatch: on the first turn of a context epoch
    /// (session start, or after a compaction or rollover) the workload facts
    /// block and the brain context, then the operator text verbatim; an
    /// ordinary turn carries only the profile's per-turn tail. The prefetch
    /// reads the operator's text only, never the facts prefix.
    async fn turn_input(&self, text: &str, epoch_start: bool) -> Result<String, LiveError> {
        let facts_prefix = match &self.workload_turns {
            Some((seat, profile, source)) if epoch_start => {
                let facts =
                    source
                        .turn_facts(seat, profile)
                        .map_err(|error| LiveError::Unavailable {
                            code: format!("workload_turn_facts: {error}"),
                        })?;
                format!("{facts}\n\n")
            }
            _ => String::new(),
        };
        let prefetch = match &self.brain_turns {
            None => None,
            Some(source) => prefetch_block(Arc::clone(source), text, epoch_start).await,
        };
        Ok(match prefetch {
            None => format!("{facts_prefix}{text}"),
            Some(block) => format!("{facts_prefix}{block}\n\n{text}"),
        })
    }

    /// The exact cannot-fit gate over one RENDERED turn — the last host
    /// check before dispatch, counting what is actually sent.
    fn guard_lane_context(
        &self,
        lane: Option<&LaneContextBudget>,
        state: Option<&VerifiedLaneState>,
        incoming: &str,
        images: &[Value],
    ) -> Result<(), LiveError> {
        let Some(budget) = lane else {
            return Ok(());
        };
        let counter = budget.counter()?;
        let incoming_tokens =
            u64::from(
                counter
                    .count_text(incoming)
                    .map_err(|error| LiveError::InvalidRequest {
                        code: "lane_context_budget".to_owned(),
                        message: format!("the rendered turn is uncountable: {error}"),
                    })?,
            );
        // A text-only turn carries NO attachments: the empty slice must
        // count zero media bytes, never the two bytes of its own `[]`
        // serialization — otherwise every native-lane turn is refused
        // before dispatch regardless of content.
        let image_tokens = if images.is_empty() {
            0
        } else {
            u64::try_from(
                serde_json::to_string(images)
                    .map_err(|_| LiveError::InvalidRequest {
                        code: "lane_context_budget".to_owned(),
                        message: "turn attachments are not countable".to_owned(),
                    })?
                    .len(),
            )
            .unwrap_or(u64::MAX)
        };
        lane_context_decision(
            budget,
            state,
            self.bridge.measured_context_watermark(),
            incoming_tokens,
            image_tokens,
        )
    }

    /// One full prompt/follow-up preparation: verify the lane's harness
    /// snapshot BEFORE any compilation (native lanes), build the turn input
    /// with the measured overhead, and gate the exact rendered dispatch.
    async fn prepare_dispatch(&self, text: &str, images: &[Value]) -> Result<String, LiveError> {
        let lane = self.current_lane()?;
        let state = self.verified_lane_state(lane.as_ref()).await?;
        let epoch = self.bridge.context_epoch();
        let epoch_start = self
            .injected_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != epoch;
        let incoming = self.turn_input(text, epoch_start).await?;
        self.guard_lane_context(lane.as_ref(), state.as_ref(), &incoming, images)?;
        self.injected_epoch
            .store(epoch, std::sync::atomic::Ordering::Release);
        Ok(incoming)
    }

    pub fn bridge(&self) -> &Arc<OmpBridge> {
        &self.bridge
    }
}

#[async_trait]
impl LiveControlBackend for BridgeControl {
    fn supports_identity_safe_dispatch(&self) -> bool {
        true
    }

    async fn bridge_ready(&self) -> bool {
        matches!(
            self.bridge.status(),
            Ok(crate::bridge::BridgeStatus::Ready)
                | Ok(crate::bridge::BridgeStatus::Starting)
                | Ok(crate::bridge::BridgeStatus::Blocked { .. })
        )
    }
    async fn process_exited(&self) -> bool {
        self.bridge.process_exited()
    }

    async fn message_outcome(
        &self,
        command_id: &odin_domain::CommandId,
    ) -> Result<Option<bool>, LiveError> {
        self.bridge
            .identified_prompt_outcome(command_id)
            .await
            .map_err(bridge_error)
    }

    async fn dispatch_message(
        &self,
        command_id: &odin_domain::CommandId,
        message: &LiveMessage,
        follow_up: bool,
    ) -> Result<bool, LiveError> {
        let (text, images) = omp_message(message)?;
        let text = self.prepare_dispatch(&text, &images).await?;
        self.bridge
            .prompt_open_loop_identified(
                command_id,
                Prompt {
                    message: text,
                    images,
                    streaming_behavior: follow_up.then_some(StreamingBehavior::FollowUp),
                },
            )
            .await
            .map_err(bridge_error)
    }

    async fn prompt(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let (text, images) = omp_message(message)?;
        let text = self.prepare_dispatch(&text, &images).await?;
        self.bridge
            .prompt_open_loop(Prompt {
                message: text,
                images,
                streaming_behavior: None,
            })
            .await
            .map_err(bridge_error)
    }

    async fn follow_up(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let (text, images) = omp_message(message)?;
        let text = self.prepare_dispatch(&text, &images).await?;
        // Let the child choose atomically: queue while streaming, start a
        // prompt if its previous turn ended before our observation arrived.
        self.bridge
            .prompt_open_loop(Prompt {
                message: text,
                images,
                streaming_behavior: Some(StreamingBehavior::FollowUp),
            })
            .await
            .map_err(bridge_error)
    }

    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let (text, images) = omp_message(message)?;
        self.bridge
            .steer(text, images)
            .await
            .map(|_| ())
            .map_err(bridge_error)
    }

    /// Checkpoints and aborts before detaching; late `agent_end` must not undo the pause.
    async fn pause(&self) -> Result<(), LiveError> {
        self.bridge.checkpoint().await.map_err(bridge_error)?;
        self.abort_turn().await?;
        self.hooks.pause().await
    }

    async fn resume(&self) -> Result<(), LiveError> {
        self.hooks.resume().await
    }

    async fn checkpoint(&self) -> Result<(), LiveError> {
        self.bridge
            .checkpoint()
            .await
            .map(|_| ())
            .map_err(bridge_error)
    }

    async fn restart(&self) -> Result<(), LiveError> {
        self.bridge.recover().await.map_err(bridge_error)?;
        // The respawned incarnation runs the launch model; recovery
        // re-asserts a journaled switch through `set_model`.
        self.set_current_model(self.launch_model.clone())
    }

    async fn rollover_fresh(
        &self,
        refusal_event: u64,
        selected_model: Option<(&ProviderName, &ModelName)>,
    ) -> Result<i64, LiveError> {
        let selected = selected_model
            .map(|(provider, model)| (provider.as_str().to_owned(), model.as_str().to_owned()));
        let epoch = self
            .bridge
            .rollover_context_refusal(refusal_event, selected.clone())
            .await
            .map_err(bridge_error)?;
        // The fresh incarnation ran the selection from its first turn (the
        // bridge re-asserts it after the respawn, before the reinjection),
        // so the tracker mirrors what the carrier really runs.
        self.set_current_model(selected.unwrap_or_else(|| self.launch_model.clone()))?;
        Ok(epoch)
    }

    async fn rehome(&self, target_node: &NodeId) -> Result<(), LiveError> {
        self.bridge.checkpoint().await.map_err(bridge_error)?;
        self.hooks.rehome(target_node).await
    }

    async fn set_model(&self, provider: &ProviderName, model: &ModelName) -> Result<(), LiveError> {
        // A guarded session only switches to a model with a declared
        // window: the extension would refuse every later request on it.
        if let Some(budgets) = &self.lane_context_budgets {
            if budgets
                .for_model(provider.as_str(), model.as_str())
                .is_none()
            {
                return Err(LiveError::InvalidRequest {
                    code: "lane_context_budget".to_owned(),
                    message: format!(
                        "{provider}/{model} has no declared context window; the switch is \
                         refused before it reaches the session"
                    ),
                });
            }
        }
        self.bridge
            .set_model(provider.as_str(), model.as_str())
            .await
            .map_err(bridge_error)?;
        self.set_current_model((provider.as_str().to_owned(), model.as_str().to_owned()))
    }

    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.bridge.abort().await.map(|_| ()).map_err(bridge_error)
    }

    async fn abort_session(&self) -> Result<(), LiveError> {
        // An already-stopped child satisfies abort; other stop failures must still propagate.
        match self.bridge.stop_ending_session().await {
            Ok(_) => Ok(()),
            Err(crate::bridge::BridgeError::Stopped) => Ok(()),
            Err(error) => Err(bridge_error(error)),
        }
    }

    /// The ordinary run stop: the daemon releases this session's backend —
    /// the bounded ladder of [`crate::bridge::OmpBridge::stop`] — while the
    /// session itself stays durable and resumable. The bridge's live row
    /// keeps publishing `ready`, so the next daemon reclaims and reattaches
    /// the session (the start-time settlement reconciles rows a stopped
    /// daemon left).
    async fn shutdown(&self) -> Result<(), LiveError> {
        self.bridge.stop().await.map(|_| ()).map_err(bridge_error)
    }

    async fn decide_permission(
        &self,
        request_id: &PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        self.bridge
            .reply_to_confirmation(
                request_id,
                matches!(decision, PermissionDecision::AllowOnce),
            )
            .await
            .map_err(bridge_error)
    }

    async fn decide_approval(
        &self,
        approval_id: &ApprovalId,
        expected_revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        self.hooks
            .decide_approval(approval_id, expected_revision, decision)
            .await
    }
}

pub struct ControlExecutor {
    backend: Arc<dyn LiveControlBackend>,
}

impl ControlExecutor {
    pub fn new(backend: Arc<dyn LiveControlBackend>) -> Self {
        Self { backend }
    }
    pub fn supports_identity_safe_dispatch(&self) -> bool {
        self.backend.supports_identity_safe_dispatch()
    }

    pub async fn apply_identified(
        &self,
        command: &odin_domain::huginn::LiveCommand,
        state: LiveSessionState,
    ) -> Result<Option<ControlEffect>, LiveError> {
        if state == LiveSessionState::Ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "an ended session cannot receive messages".to_owned(),
            });
        }
        let (message, follow_up) = match &command.body {
            LiveCommandBody::Prompt { message } => (message, false),
            LiveCommandBody::FollowUp { message } => (message, true),
            _ => return self.apply(&command.body, state).await.map(Some),
        };
        if let Some(delivered) = self.backend.message_outcome(&command.command_id).await? {
            return Ok(delivered.then(ControlEffect::unchanged));
        }
        if !self
            .backend
            .dispatch_message(&command.command_id, message, follow_up)
            .await?
        {
            return Ok(None);
        }
        let mut effect = ControlEffect::unchanged();
        if !follow_up {
            effect.state = Some(LiveSessionState::Running);
        }
        Ok(Some(effect))
    }

    pub(super) async fn apply(
        &self,
        body: &LiveCommandBody,
        state: LiveSessionState,
    ) -> Result<ControlEffect, LiveError> {
        // Internal recovery bypasses client command applicability, not
        // terminality. Refuse before touching a closed session's backend.
        if state == LiveSessionState::Ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "an ended session cannot be restarted or controlled".to_owned(),
            });
        }
        let mut effect = ControlEffect::unchanged();
        match body {
            LiveCommandBody::Prompt { message } => {
                self.backend.prompt(message).await?;
                effect.state = Some(LiveSessionState::Running);
            }
            LiveCommandBody::FollowUp { message } => self.backend.follow_up(message).await?,
            LiveCommandBody::Steer { message } => self.backend.steer(message).await?,
            LiveCommandBody::Pause => {
                self.backend.pause().await?;
                effect.state = Some(LiveSessionState::Detached);
            }
            LiveCommandBody::Resume => {
                self.backend.resume().await?;
                effect.state = Some(LiveSessionState::Idle);
            }
            LiveCommandBody::Checkpoint => self.backend.checkpoint().await?,
            LiveCommandBody::Restart => {
                self.backend.restart().await?;
                effect.state = Some(LiveSessionState::Idle);
                effect.reclaim_epoch = true;
            }
            LiveCommandBody::Rehome { target_node } => {
                self.backend.rehome(target_node).await?;
                effect.target_node = Some(target_node.clone());
                effect.state = Some(LiveSessionState::Idle);
                effect.reclaim_epoch = true;
            }
            LiveCommandBody::SetModel { provider, model } => {
                self.backend.set_model(provider, model).await?;
                effect.provider = Some(provider.clone());
                effect.model = Some(model.clone());
            }
            LiveCommandBody::Abort {
                scope: AbortScope::CurrentTurn,
            } => {
                self.backend.abort_turn().await?;
                effect.state = Some(LiveSessionState::Idle);
            }
            LiveCommandBody::Abort {
                scope: AbortScope::Session,
            } => {
                self.backend.abort_session().await?;
                effect.state = Some(LiveSessionState::Ended);
                effect.terminate = true;
            }
            LiveCommandBody::DecidePermission {
                request_id,
                decision,
            } => {
                self.backend
                    .decide_permission(request_id, *decision)
                    .await?;
                effect.state = Some(LiveSessionState::Running);
            }
            LiveCommandBody::DecideApproval {
                approval_id,
                expected_revision,
                decision,
            } => {
                self.backend
                    .decide_approval(approval_id, *expected_revision, *decision)
                    .await?;
                let notice = match decision {
                    ApprovalDecision::Approve => format!(
                        "[host] Approval {approval_id} was granted. Continue the exact pending \
                         call with unchanged arguments; the kernel consumes approval once."
                    ),
                    ApprovalDecision::Reject => format!(
                        "[host] Approval {approval_id} was denied. Do not retry that call; \
                         continue the conversation without the refused effect."
                    ),
                };
                let message =
                    LiveMessage::new(vec![LiveContentBlock::Text(notice)]).map_err(|error| {
                        LiveError::InvalidRequest {
                            code: "approval_continuation".to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                if state == LiveSessionState::Idle {
                    self.backend.prompt(&message).await?;
                    effect.state = Some(LiveSessionState::Running);
                } else {
                    self.backend.follow_up(&message).await?;
                }
            }
        }
        Ok(effect)
    }

    /// The ordinary stop of this daemon's hold on the session: the backend
    /// run stops while the session stays durable and resumable.
    pub async fn shutdown(&self) -> Result<(), LiveError> {
        self.backend.shutdown().await
    }

    /// The session-ending teardown for the actor's terminal stop (`end`):
    /// the backend's session abort — the same operation the whole-session
    /// `Abort` command applies — stops the bridge run AND retires its
    /// durable row `Ended`, so the ended session can never be reclaimed by
    /// a later launch. `shutdown` (not this) is the resumable stop.
    pub async fn end_session(&self) -> Result<(), LiveError> {
        self.backend.abort_session().await
    }

    pub async fn bridge_ready(&self) -> bool {
        self.backend.bridge_ready().await
    }
    /// Whether child exit or teardown completed.
    pub async fn process_exited(&self) -> bool {
        self.backend.process_exited().await
    }

    /// The internal typed context-refusal rollover: like `Restart`, system
    /// recovery that bypasses client command applicability (never
    /// terminality), always reclaims the epoch, and always settles `Idle`.
    /// The journaled model selection (`selected_model`, `None` while the
    /// session runs its launch pair) is re-asserted by the bridge after
    /// the respawn and BEFORE the reinjection turn, so the fresh
    /// incarnation's first turn runs the selected model and its context
    /// budget.
    pub async fn apply_rollover_fresh(
        &self,
        refusal_event: u64,
        state: LiveSessionState,
        selected_model: Option<(&ProviderName, &ModelName)>,
    ) -> Result<ControlEffect, LiveError> {
        if state == LiveSessionState::Ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "an ended session cannot be restarted or controlled".to_owned(),
            });
        }
        let epoch = self
            .backend
            .rollover_fresh(refusal_event, selected_model)
            .await?;
        let mut effect = ControlEffect::unchanged();
        effect.state = Some(LiveSessionState::Idle);
        effect.reclaim_epoch = true;
        effect.epoch = Some(epoch);
        Ok(effect)
    }
}

fn omp_message(message: &LiveMessage) -> Result<(String, Vec<Value>), LiveError> {
    message
        .validate()
        .map_err(|error| LiveError::InvalidRequest {
            code: "invalid_message".to_owned(),
            message: error.to_string(),
        })?;
    let mut text = String::new();
    let mut attachments = Vec::new();
    for block in &message.content {
        match block {
            LiveContentBlock::Text(value) => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(value);
            }
            other => attachments.push(serde_json::to_value(other).map_err(|_| {
                LiveError::InvalidRequest {
                    code: "invalid_message_block".to_owned(),
                    message: "message attachment could not be encoded".to_owned(),
                }
            })?),
        }
    }
    if text.is_empty() {
        text.push_str("Attached content follows.");
    }
    Ok((text, attachments))
}

fn bridge_error(error: crate::bridge::BridgeError) -> LiveError {
    match error {
        error @ crate::bridge::BridgeError::CommandFailed { .. } => LiveError::InvalidRequest {
            code: "omp_command_failed".to_owned(),
            message: error.to_string(),
        },
        // Preserve epoch mismatch separately from retryable unavailability; never clamp epochs.
        crate::bridge::BridgeError::StaleBinding { requested, actual } => {
            match (
                checked_session_epoch(requested),
                checked_session_epoch(actual),
            ) {
                (Ok(expected), Ok(actual)) => LiveError::EpochMismatch { expected, actual },
                (Err(code), _) | (_, Err(code)) => LiveError::Unavailable { code },
            }
        }
        // The bridge's own failure travels with the code: an erased cause
        // left a wedged vehicle undiagnosable ("omp_bridge" and nothing else).
        error => LiveError::Unavailable {
            code: format!("omp_bridge: {error}"),
        },
    }
}

/// A prefetch miss is not a turn failure: the operator text still goes.
async fn prefetch_block(
    source: Arc<dyn BrainTurnContext>,
    text: &str,
    epoch_start: bool,
) -> Option<String> {
    let text = text.to_owned();
    match tokio::task::spawn_blocking(move || source.prefetch(&text, epoch_start)).await {
        Ok(Ok(block)) => block,
        Ok(Err(error)) => {
            tracing::warn!(
                "odind: brain prefetch failed; sending the turn without memory: {error}"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                "odind: brain prefetch task failed; sending the turn without memory: {error}"
            );
            None
        }
    }
}
/// Checked i64 → SessionEpoch: negative, zero, or out-of-range binding
/// epochs fail typed instead of being defaulted.
pub(super) fn checked_session_epoch(
    value: i64,
) -> Result<odin_domain::huginn::SessionEpoch, String> {
    let value = u64::try_from(value).map_err(|_| "binding epoch is negative".to_owned())?;
    if value == 0 {
        return Err("binding epoch is zero".to_owned());
    }
    Ok(odin_domain::huginn::SessionEpoch::new(value))
}

#[cfg(test)]
mod lane_context_tests {
    use super::{lane_context_decision, verify_lane_state, LaneContextBudget, VerifiedLaneState};
    use odin_brain::context::{PINNED_TOKENIZER_ID, QWEN3_TOKENIZER_ID};
    use odin_domain::huginn::LiveError;
    use odin_domain::knowledge::ids::TokenizerId;

    fn lane(
        provider: &str,
        model: &str,
        window: u64,
        reserve: u64,
        tokenizer: &str,
    ) -> LaneContextBudget {
        LaneContextBudget {
            provider: provider.to_owned(),
            model: model.to_owned(),
            window,
            reserve,
            tokenizer: TokenizerId::new(tokenizer).expect("fixture tokenizer id"),
        }
    }

    fn byte_lane(window: u64, reserve: u64) -> LaneContextBudget {
        lane(
            "gateway",
            "herald-model",
            window,
            reserve,
            PINNED_TOKENIZER_ID,
        )
    }

    fn qwen3_lane(window: u64, reserve: u64) -> LaneContextBudget {
        lane(
            "gateway",
            "herald-model",
            window,
            reserve,
            QWEN3_TOKENIZER_ID,
        )
    }

    fn snapshot(usage: u64) -> VerifiedLaneState {
        VerifiedLaneState {
            context_usage_tokens: usage,
        }
    }

    /// One faithful harness get_state payload: the exact shape the pinned
    /// rpc-mode serializes (`model` with provider/id/contextWindow/tokenizer,
    /// plus `contextUsage.tokens`).
    fn harness_state(
        provider: &str,
        id: &str,
        window: u64,
        tokenizer: &str,
        usage: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "model": {
                "provider": provider,
                "id": id,
                "contextWindow": window,
                "tokenizer": tokenizer,
                "api": "openai-completions",
            },
            "contextUsage": { "tokens": usage, "contextWindow": window, "percent": 1.0 },
        })
    }

    #[test]
    fn a_snapshot_verifies_only_under_every_declared_identity() {
        let lane = qwen3_lane(16_384, 6_144);
        let exact = harness_state("gateway", "herald-model", 16_384, "qwen3", 4_000);
        let verified = verify_lane_state(&lane, &exact).expect("exact identity verifies");
        assert_eq!(verified.context_usage_tokens, 4_000);
        for (detail, tampered) in [
            (
                "provider",
                harness_state("other", "herald-model", 16_384, "qwen3", 4_000),
            ),
            (
                "id",
                harness_state("gateway", "other-model", 16_384, "qwen3", 4_000),
            ),
            (
                "window",
                harness_state("gateway", "herald-model", 32_768, "qwen3", 4_000),
            ),
            (
                "tokenizer",
                harness_state("gateway", "herald-model", 16_384, "glm5", 4_000),
            ),
            (
                "usage",
                serde_json::json!({
                    "model": {
                        "provider": "gateway",
                        "id": "herald-model",
                        "contextWindow": 16_384,
                        "tokenizer": "qwen3",
                    }
                }),
            ),
        ] {
            let error = verify_lane_state(&lane, &tampered)
                .expect_err("{detail} mismatch must refuse typed");
            assert!(
                matches!(error, LiveError::Unavailable { .. }),
                "{detail} mismatch is a typed unavailability, never a guessed plan: {error:?}"
            );
        }
        // Byte lanes measure the request directly and must not consume harness snapshots.
        let byte = byte_lane(16_384, 6_144);
        assert!(byte.byte_policy());
        assert!(!lane.byte_policy());
        assert!(
            verify_lane_state(&byte, &exact).is_err(),
            "a byte lane never consumes harness token snapshots"
        );
        assert_eq!(
            byte.stage(),
            "gateway|herald-model|16384|6144|odin.tokenizer.utf8-bytes.v1",
            "the staged declaration carries the exact five-field contract"
        );
        assert_eq!(
            lane.stage(),
            "gateway|herald-model|16384|6144|odin.tokenizer.qwen3.v1",
            "the native lane stages its exact declared identity"
        );
    }

    #[test]
    fn a_native_estimate_over_the_window_never_refuses_the_dispatch_host_side() {
        // The host estimate (harness contextUsage) is planning input, never
        // enforcement: even an estimate past the window dispatches, because
        // the trusted extension's final structured fit at
        // before_provider_request owns the real payload and the independent
        // guard there owns refusal. Only missing snapshots and media refuse
        // host-side on native lanes.
        let lane = qwen3_lane(16_384, 6_144);
        let state = snapshot(15_000);
        lane_context_decision(&lane, Some(&state), None, 20_000, 0)
            .expect("a stale estimate never refuses a native dispatch host-side");
    }

    #[test]
    fn a_native_lane_without_a_verified_snapshot_is_refused_not_planned_as_zero() {
        let lane = qwen3_lane(16_384, 6_144);
        let error = lane_context_decision(&lane, None, None, 100, 0)
            .expect_err("no snapshot is a typed refusal, never a zero-overhead plan");
        let LiveError::Unavailable { code } = error else {
            panic!("missing snapshot is a typed unavailability: {error:?}");
        };
        assert!(
            code.starts_with("lane_context_state"),
            "the refusal names the snapshot seam: {code}"
        );
    }

    #[test]
    fn a_native_lane_refuses_media_before_dispatch() {
        let lane = qwen3_lane(1_048_576, 6_144);
        let state = snapshot(1_000);
        let error = lane_context_decision(&lane, Some(&state), None, 100, 512)
            .expect_err("image attachments are outside the declared text policy");
        assert!(matches!(error, LiveError::Unavailable { .. }), "{error:?}");
    }

    #[test]
    fn the_byte_lane_keeps_the_measured_watermark_law() {
        let lane = byte_lane(16_384, 6_144);
        // Unchanged first-turn semantics: without a settled watermark the
        // byte lane has no measured accumulated context and inventing one
        // is forbidden; the extension's whole-request count stays the guard.
        lane_context_decision(&lane, None, None, 100_000, 0)
            .expect("the byte lane without a watermark stays unguarded host-side");
        lane_context_decision(&lane, None, Some(10_000), 240, 0)
            .expect("10000 + 240 + 6144 <= the window fits");
        let error = lane_context_decision(&lane, None, Some(10_000), 241, 0)
            .expect_err("past the boundary refuses");
        assert!(matches!(error, LiveError::Unavailable { .. }), "{error:?}");
        // Attachment serialization stays conservatively charged in bytes.
        assert!(
            lane_context_decision(&lane, None, Some(10_000), 240, 1).is_err(),
            "image bytes count toward the byte lane's whole-request bound"
        );
    }
}

#[cfg(test)]
mod lane_budget_set_tests {
    use super::{LaneContextBudget, LaneContextBudgets};
    use odin_domain::knowledge::ids::TokenizerId;

    fn lane(model: &str, window: u64) -> LaneContextBudget {
        LaneContextBudget {
            provider: "gateway".to_owned(),
            model: model.to_owned(),
            window,
            reserve: 500,
            tokenizer: TokenizerId::new("odin.tokenizer.utf8-bytes.v1").expect("tokenizer"),
        }
    }

    #[test]
    fn the_budget_in_force_is_the_declared_lane_of_the_named_model() {
        assert!(LaneContextBudgets::new(Vec::new()).is_none());
        let budgets =
            LaneContextBudgets::new(vec![lane("zai-glm", 8000), lane("glm-flash", 20000)])
                .expect("declared set");
        assert_eq!(
            budgets
                .for_model("gateway", "glm-flash")
                .map(|lane| lane.window),
            Some(20000)
        );
        assert!(budgets.for_model("gateway", "kubert-mini").is_none());
        assert!(budgets.for_model("other", "zai-glm").is_none());
        assert_eq!(
            budgets.stage(),
            "gateway|zai-glm|8000|500|odin.tokenizer.utf8-bytes.v1;\
             gateway|glm-flash|20000|500|odin.tokenizer.utf8-bytes.v1"
        );
    }
}

#[cfg(test)]
mod prefetch_tests {
    use std::sync::Arc;

    use odin_domain::huginn::LiveError;

    use super::{prefetch_block, BrainTurnContext};

    struct Broken;

    impl BrainTurnContext for Broken {
        fn prefetch(&self, _text: &str, _epoch_start: bool) -> Result<Option<String>, LiveError> {
            Err(LiveError::Unavailable {
                code: "silverbullet down".to_owned(),
            })
        }
    }

    struct Hit;

    impl BrainTurnContext for Hit {
        fn prefetch(&self, _text: &str, _epoch_start: bool) -> Result<Option<String>, LiveError> {
            Ok(Some("remembered fact".to_owned()))
        }
    }

    #[tokio::test]
    async fn a_prefetch_miss_sends_the_turn_without_memory() {
        let missed = prefetch_block(Arc::new(Broken), "the prompt", true).await;
        assert!(missed.is_none());
        let hit = prefetch_block(Arc::new(Hit), "the prompt", true).await;
        assert_eq!(hit.as_deref(), Some("remembered fact"));
    }
}
