//! Evidence-backed learning on a cheap gateway lane. Owner-turn reviews run
//! in the background; task capture waits for its durable terminal receipt.
//! Registration precedes review work. Background failure/cancellation receives
//! a terminal audit row; uncertain task effects remain pending to prevent replay.

use std::sync::Arc;

use odin_brain::learn::{BrainState, Edit, Learned, Namespaces, Provenance};
use odin_domain::{ProjectId, SeatId};
use serde::Deserialize;
use serde_json::{json, Value};

const KEY_ENV: &str = "LITELLM_MASTER_KEY";
pub const LEARNED_AUDIT_KIND: &str = "brain.learned";
pub const REVIEW_PENDING_AUDIT_KIND: &str = "brain.review.pending";
pub const REVIEW_COMPLETED_AUDIT_KIND: &str = "brain.review.completed";
const EXCHANGE_CHARS: usize = 6_000;
const ENTRY_CHARS: usize = 400;

/// One settled exchange a seat may learn from.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub seat: SeatId,
    pub session: String,
    /// Delegating parent, for a task review; absent for direct turns.
    pub parent_session: Option<String>,
    pub project: Option<ProjectId>,
    /// `turn` (an owner turn) or `task` (a delegated task).
    pub trigger: &'static str,
    /// Exact conversation asks covered by this exchange (including queued asks).
    pub turn_keys: Vec<String>,
    /// Durable Result sequence for direct turns and delegated tasks.
    pub sequence: Option<u64>,
    pub asked: String,
    pub answered: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("seat {0} declares no review lane")]
    NoLane(SeatId),
    #[error("no vault is configured")]
    NoVault,
    #[error("the gateway key {KEY_ENV} is not in the daemon environment")]
    NoKey,
    #[error("hermes.review_gateway is not configured")]
    NoGateway,
    #[error("the review lane failed: {0}")]
    Lane(String),
    #[error("the review answer is not an edit list: {0}")]
    Answer(String),
    #[error("learning changes committed but their audit is unavailable: {0}")]
    Journal(String),
    #[error(transparent)]
    State(#[from] odin_brain::learn::LearnError),
}

#[derive(Debug, thiserror::Error)]
pub enum TaskReviewError {
    #[error("invalid task review identity")]
    Identity,
    #[error("task review dependency failed: {0}")]
    Dependency(String),
    #[error("task review has an uncertain prior attempt; refusing duplicate learning; operator investigation required (no automatic reconciliation)")]
    Uncertain,
}

#[derive(Deserialize)]
struct Edits {
    edits: Vec<Edit>,
}

static REVIEWS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The one serialization of managed brain mutations, held from a caller's
/// selection of its edits through their application and released before
/// any audit, log or refresh. Never held across a model call.
pub(crate) struct ReviewMutation {
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl ReviewMutation {
    pub(crate) fn acquire() -> Self {
        Self {
            _serial: REVIEWS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }
}

// Task capture is synchronous: its durable terminal receipt, not spawn success,
// discharges the owner's capture marker. Separate from the apply lock below.
static TASK_REVIEWS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An accepted review owns its terminal event until no more writes can occur.
/// Moving this into the worker closes the registration/spawn gap; dropping an
/// unrun/cancelled worker reports failure, never successful settlement.
pub struct ReviewObligation {
    runtime: Arc<super::HermesRuntime>,
    id: String,
    session: String,
    parent_session: Option<String>,
    trigger: &'static str,
    sequence: Option<u64>,
    turn_keys: Vec<String>,
    completed: bool,
}

pub enum ReviewOutcome {
    Settled(usize),
    Skipped(String),
    Failed(String),
}

impl ReviewObligation {
    pub fn complete(mut self, outcome: ReviewOutcome) {
        self.finish(outcome);
    }

    fn run(self, work: impl FnOnce() -> Result<usize, ReviewError>) {
        let outcome = match work() {
            Ok(applied) => ReviewOutcome::Settled(applied),
            Err(ReviewError::NoLane(_)) => {
                ReviewOutcome::Skipped("seat declares no review lane".into())
            }
            Err(error) => ReviewOutcome::Failed(error.to_string()),
        };
        // The worker and every apply have returned. This obligation can no
        // longer issue a write, even when an earlier edit preceded a failure.
        self.complete(outcome);
    }

    fn finish(&mut self, outcome: ReviewOutcome) {
        self.completed = true;
        let (status, applied, reason) = match outcome {
            ReviewOutcome::Settled(applied) => ("settled", Some(applied), None),
            ReviewOutcome::Skipped(reason) => ("skipped", None, Some(reason)),
            ReviewOutcome::Failed(reason) => ("failed", None, Some(reason)),
        };
        if let Err(error) = self.journal(REVIEW_COMPLETED_AUDIT_KIND, status, applied, reason) {
            tracing::error!(
                review = %self.id,
                error = %error,
                "odind: brain review completion journal failed reviewId={} error={error}",
                self.id
            );
        }
    }

    fn journal(
        &self,
        kind: &str,
        status: &str,
        applied: Option<usize>,
        reason: Option<String>,
    ) -> Result<(), String> {
        use odin_ledger::audit::{NewAuditEvent, RedactedPayload};
        let payload = json!({
            "reviewId": self.id,
            "session": self.session,
            "parentSession": self.parent_session,
            "trigger": self.trigger,
            "sequence": self.sequence,
            "turnKeys": self.turn_keys,
            "status": status,
            "applied": applied,
            "reason": reason,
        });
        let event = NewAuditEvent {
            event_id: odin_domain::EventId::new(format!("{kind}:{}", self.id))
                .map_err(|error| error.to_string())?,
            kind: kind.to_owned(),
            actor: odin_domain::Actor::system(super::RUNTIME_ISSUER)
                .map_err(|error| error.to_string())?,
            scope: Default::default(),
            evidence: Vec::new(),
            payload: RedactedPayload::new(payload.clone(), odin_domain::Redaction::None)
                .map_err(|error| error.to_string())?,
            occurred_at: super::now_utc(),
        };
        self.runtime
            .purchase_ledger
            .lock()
            .map_err(|_| "the authority ledger lock is poisoned".to_owned())?
            .append_audit_event(event)
            .map_err(|error| error.to_string())?;
        tracing::info!(kind = %kind, "odind: {kind} {payload}");
        Ok(())
    }
}

impl Drop for ReviewObligation {
    fn drop(&mut self) {
        if !self.completed {
            self.finish(ReviewOutcome::Failed(
                "review worker dropped before completion".into(),
            ));
        }
    }
}

impl super::HermesRuntime {
    /// Reviews one exact delegated result, returning only after its successful
    /// terminal receipt is durable. Reopening the same authority ledger retains
    /// deduplication. Proven pre-effect failures remain retryable; uncertain
    /// attempts stay pending and refuse replay. Serialization is daemon-local.
    pub fn review_task_completion(
        self: &Arc<Self>,
        exchange: Exchange,
    ) -> Result<(), TaskReviewError> {
        self.review_task_completion_with(&exchange, || self.review(&exchange))
    }

    fn review_task_completion_with(
        self: &Arc<Self>,
        exchange: &Exchange,
        work: impl FnOnce() -> Result<usize, ReviewError>,
    ) -> Result<(), TaskReviewError> {
        if exchange.trigger != "task"
            || exchange.sequence.is_none()
            || exchange.parent_session.is_none()
            || !exchange.turn_keys.is_empty()
        {
            return Err(TaskReviewError::Identity);
        }
        let _serial = TASK_REVIEWS
            .lock()
            .map_err(|_| TaskReviewError::Dependency("the task review lock is poisoned".into()))?;
        if self.task_review_captured(exchange)? {
            return Ok(());
        }
        let mut review = self
            .register_review(
                exchange.session.clone(),
                "task",
                exchange.sequence,
                Vec::new(),
                exchange.parent_session.clone(),
            )
            .map_err(TaskReviewError::Dependency)?;
        // This synchronous task owns explicit settlement. Unwinding or a crash
        // must leave its durable obligation pending, not manufacture a terminal
        // failure while application effects are unknown.
        review.completed = true;
        let (status, applied, reason, result) = match work() {
            Ok(applied) => ("settled", Some(applied), None, Ok(())),
            Err(ReviewError::NoLane(_)) => (
                "skipped",
                None,
                Some("seat declares no review lane".to_owned()),
                Ok(()),
            ),
            Err(ReviewError::State(_) | ReviewError::Journal(_)) => {
                // Apply may have committed before failing. Keep the accepted
                // obligation pending for operator investigation, never claim settlement.
                return Err(TaskReviewError::Uncertain);
            }
            Err(error) => {
                let reason = format!("pre-effect task review failure: {error}");
                let failure = TaskReviewError::Dependency(reason.clone());
                ("failed", None, Some(reason), Err(failure))
            }
        };
        // An unacknowledged completion stays pending: effects may already exist.
        review
            .journal(REVIEW_COMPLETED_AUDIT_KIND, status, applied, reason)
            .map_err(TaskReviewError::Dependency)?;
        result
    }

    fn task_review_captured(&self, exchange: &Exchange) -> Result<bool, TaskReviewError> {
        let ledger = self.purchase_ledger.lock().map_err(|_| {
            TaskReviewError::Dependency("the authority ledger lock is poisoned".into())
        })?;
        let mut after = 0;
        let mut accepted = std::collections::BTreeSet::new();
        loop {
            let events = ledger
                .audit_events_after(after, 256)
                .map_err(|error| TaskReviewError::Dependency(error.to_string()))?;
            if events.is_empty() {
                return if accepted.is_empty() {
                    Ok(false)
                } else {
                    Err(TaskReviewError::Uncertain)
                };
            }
            for event in events {
                after = event.sequence;
                let payload = &event.payload;
                if payload["session"].as_str() != Some(exchange.session.as_str())
                    || payload["parentSession"].as_str() != exchange.parent_session.as_deref()
                    || payload["trigger"].as_str() != Some("task")
                    || payload["sequence"].as_u64() != exchange.sequence
                    || payload["turnKeys"] != json!([])
                {
                    continue;
                }
                let Some(id) = payload["reviewId"].as_str() else {
                    continue;
                };
                if event.kind == REVIEW_PENDING_AUDIT_KIND
                    && payload["status"].as_str() == Some("pending")
                {
                    accepted.insert(id.to_owned());
                } else if event.kind == REVIEW_COMPLETED_AUDIT_KIND
                    && accepted.contains(id)
                    && (payload["status"].as_str() == Some("settled")
                        || (payload["status"].as_str() == Some("skipped")
                            && payload["reason"].as_str() == Some("seat declares no review lane")))
                {
                    return Ok(true);
                } else if event.kind == REVIEW_COMPLETED_AUDIT_KIND
                    && payload["status"].as_str() == Some("failed")
                    && payload["reason"].as_str().is_some_and(|reason| {
                        reason.starts_with("pre-effect task review failure: ")
                    })
                {
                    accepted.remove(id);
                }
            }
        }
    }

    /// Journals the review before asynchronous work; registration failure refuses before writes.
    pub fn register_review(
        self: &Arc<Self>,
        session: String,
        trigger: &'static str,
        sequence: Option<u64>,
        turn_keys: Vec<String>,
        parent_session: Option<String>,
    ) -> Result<ReviewObligation, String> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = format!(
            "{}-{}",
            super::now_utc().unix_timestamp_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let mut review = ReviewObligation {
            runtime: Arc::clone(self),
            id,
            session,
            trigger,
            sequence,
            turn_keys,
            parent_session,
            completed: true,
        };
        review.journal(REVIEW_PENDING_AUDIT_KIND, "pending", None, None)?;
        review.completed = false;
        Ok(review)
    }

    /// Registers synchronously, then starts the background review.
    pub fn review_after(self: &Arc<Self>, exchange: Exchange) {
        match self.register_review(
            exchange.session.clone(),
            exchange.trigger,
            exchange.sequence,
            exchange.turn_keys.clone(),
            exchange.parent_session.clone(),
        ) {
            Ok(review) => self.review_registered(exchange, review),
            Err(error) => tracing::error!(
                session = %exchange.session,
                error = %error,
                "odind: brain review registration failed session={} error={error}",
                exchange.session
            ),
        }
    }

    /// Continues an obligation accepted before asynchronous exchange resolution.
    pub fn review_registered(self: &Arc<Self>, exchange: Exchange, review: ReviewObligation) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            review.complete(ReviewOutcome::Skipped("no async runtime".into()));
            return;
        };
        let runtime = Arc::clone(self);
        handle.spawn_blocking(move || review.run(|| runtime.review(&exchange)));
    }

    /// The brain-state repo over the vault's generated memories.
    pub fn brain_state(&self) -> Result<BrainState, ReviewError> {
        let vault = self.settings().vault.as_ref().ok_or(ReviewError::NoVault)?;
        let seat_namespace =
            odin_brain::source::silverbullet::memory_namespace(&vault.generated_namespace, "x")
                .map_err(|error| ReviewError::Lane(error.to_string()))?;
        let memories = vault.vault_root.join(seat_namespace.trim_end_matches("/x"));
        Ok(BrainState::open(
            memories,
            self.settings().state_dir.join("brain.git"),
        )?)
    }

    fn review(&self, exchange: &Exchange) -> Result<usize, ReviewError> {
        // No lane is a skip. A missing gateway is a failure, so it must not
        // precede the lane check or seats that do not review retry forever.
        let lane = self
            .review_lane(&exchange.seat)
            .ok_or_else(|| ReviewError::NoLane(exchange.seat.clone()))?;
        let gateway = self.review_gateway().ok_or(ReviewError::NoGateway)?;
        let state = self.brain_state()?;
        let namespaces = self.namespaces(&exchange.seat, exchange.project.as_ref());
        let mut entries = Vec::new();
        for namespace in namespaces.writable() {
            entries.extend(state.entries(namespace)?);
        }
        let prompt = review_prompt(exchange, &namespaces, &entries);
        let answer = ask_lane(&review_endpoint(&gateway), &lane, &exchange.seat, &prompt)?;
        let edits = parse_edits(&answer)?;
        if edits.is_empty() {
            return Ok(0);
        }
        let provenance = Provenance {
            seat: exchange.seat.to_string(),
            session: exchange.session.clone(),
            trigger: exchange.trigger.to_owned(),
        };
        let (learned, _) = self.learn(
            ReviewMutation::acquire(),
            &state,
            &namespaces,
            &edits,
            &provenance,
            exchange.project.as_ref(),
        )?;
        Ok(learned.len())
    }

    /// Writable namespaces for one seat: its own directory when granted, the
    /// bound project's when that route exists, and the profile only when this
    /// seat's declaration grants that write.
    pub(crate) fn namespaces(&self, seat: &SeatId, project: Option<&ProjectId>) -> Namespaces {
        let grant = self.memory_grant(seat);
        let seat_memory = self.memory_name(seat, None);
        let project_memory = self.memory_name(seat, project);
        let project = (project_memory != seat_memory).then_some(project_memory);
        let mut writable = Vec::new();
        if grant.own {
            writable.push(seat_memory.clone());
        }
        if let Some(name) = &project {
            writable.push(name.clone());
        }
        if let Some(profile) = &grant.profile {
            writable.push(profile.clone());
        }
        Namespaces {
            colin: grant.profile,
            project,
            seat: seat_memory,
            writable,
        }
    }

    /// The one write path into the brain: applies `edits` (one commit
    /// each), logs every learned and refused edit, and journals one
    /// `brain.learned` audit row per learned commit. `mutation`, held since
    /// the caller selected `edits`, is released as soon as they are applied.
    pub(crate) fn learn(
        &self,
        mutation: ReviewMutation,
        state: &BrainState,
        namespaces: &Namespaces,
        edits: &[Edit],
        provenance: &Provenance,
        project: Option<&ProjectId>,
    ) -> Result<(Vec<Learned>, Vec<String>), ReviewError> {
        let applied = state.apply(namespaces, edits, provenance);
        drop(mutation);
        let (learned, refused) = applied?;
        for reason in &refused {
            tracing::error!(
                seat = %provenance.seat,
                session = %provenance.session,
                "odind: brain edit refused seat={} session={} trigger={} reason={reason}",
                provenance.seat, provenance.session, provenance.trigger
            );
        }
        let mut audit_failures = Vec::new();
        for applied in &learned {
            tracing::info!(
                seat = %provenance.seat,
                session = %provenance.session,
                "odind: brain.learned seat={} session={} trigger={} action={:?} kind={} page={} commit={}",
                provenance.seat,
                provenance.session,
                provenance.trigger,
                applied.action,
                applied.kind.as_str(),
                applied.page,
                applied.commit
            );
            if let Err(error) = self.journal_learned(provenance, project, applied) {
                tracing::error!(
                    seat = %provenance.seat,
                    error = %error,
                    "odind: brain.learned journal failed seat={} commit={} error={error}",
                    provenance.seat, applied.commit
                );
                audit_failures.push(format!("{}@{}: {error}", applied.page, applied.commit));
            }
        }
        if !audit_failures.is_empty() {
            return Err(ReviewError::Journal(audit_failures.join("; ")));
        }
        Ok((learned, refused))
    }

    /// One `brain.learned` audit row per learned commit in the authority
    /// ledger, beside the commit in brain.git. Journaling a commit again
    /// keeps its existing row, so a retry can repair a lost write.
    pub(super) fn journal_learned(
        &self,
        provenance: &Provenance,
        project: Option<&ProjectId>,
        applied: &Learned,
    ) -> Result<(), String> {
        use odin_ledger::audit::{append_audit_event_in_tx, NewAuditEvent, RedactedPayload};
        let event = NewAuditEvent {
            event_id: odin_domain::EventId::new(format!("{LEARNED_AUDIT_KIND}:{}", applied.commit))
                .map_err(|error| error.to_string())?,
            kind: LEARNED_AUDIT_KIND.to_owned(),
            actor: odin_domain::Actor::system(super::RUNTIME_ISSUER)
                .map_err(|error| error.to_string())?,
            scope: odin_domain::Scope {
                seat: Some(
                    SeatId::new(provenance.seat.clone()).map_err(|error| error.to_string())?,
                ),
                project: project.cloned(),
                ..Default::default()
            },
            evidence: Vec::new(),
            payload: RedactedPayload::new(
                json!({
                    "session": provenance.session,
                    "trigger": provenance.trigger,
                    "action": format!("{:?}", applied.action).to_lowercase(),
                    "kind": applied.kind.as_str(),
                    "page": applied.page,
                    "commit": applied.commit,
                }),
                odin_domain::Redaction::None,
            )
            .map_err(|error| error.to_string())?,
            occurred_at: super::now_utc(),
        };
        self.purchase_ledger
            .lock()
            .map_err(|_| "the authority ledger lock is poisoned".to_owned())?
            .with_tx(|transaction| append_audit_event_in_tx(transaction, event))
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn clip(text: &str, chars: usize) -> String {
    let mut clipped: String = text.chars().take(chars).collect();
    if text.chars().count() > chars {
        clipped.push_str(" …");
    }
    clipped
}

const REVIEW_SYSTEM: &str = "You keep an assistant's core memory: short durable entries that every \
future session of this seat starts with. Read the exchange and decide whether anything in it is \
worth keeping. Keep only what Scopes lists: lasting facts and preferences about the owner (scope \
colin, only when Scopes lists it); lessons about how this seat should work (scope seat); facts \
about the current project or repository such as its build and test commands (scope project, only \
when Scopes lists it). A task that explicitly reports a durable fact for later sessions — how a \
repository builds, a recurring constraint, a decision — is kept. Most exchanges teach nothing: \
then answer {\"edits\":[]}. Never keep secrets, credentials, one-off transient details, or anything \
an entry already says. When the owner says something an entry says is wrong, revert that entry \
(action revert, its id) and add the correction if one was given; when a fact changed, update the \
entry; when it no longer holds, retire it. kind is memory (a fact), prompt (a standing \
instruction), skill (a reusable procedure: content is the steps) or subagent (a helper worth \
delegating to). A memory or prompt entry holds at most 600 bytes, a skill or subagent at most \
4000: keep entries short. At most three edits. Answer only JSON: {\"edits\":[{\"action\":\
\"add|update|retire|revert\",\"kind\":\"memory|prompt|skill|subagent\",\"scope\":\"colin|seat|project\",\
\"id\":\"<entry id, for update, retire or revert>\",\"title\":\"<a few words>\",\"content\":\"<the entry>\",\
\"evidence\":\"<what in the exchange shows it>\"}]}";

fn scope_list(namespaces: &Namespaces) -> String {
    let mut scopes = Vec::new();
    if namespaces
        .colin
        .as_ref()
        .is_some_and(|name| namespaces.grants(name))
    {
        scopes.push("colin");
    }
    if namespaces.grants(&namespaces.seat) {
        scopes.push("seat");
    }
    if namespaces
        .project
        .as_ref()
        .is_some_and(|name| namespaces.grants(name))
    {
        scopes.push("project");
    }
    if scopes.is_empty() {
        "none".to_owned()
    } else if namespaces.project.is_none() {
        format!("{} (this session has no project memory)", scopes.join(", "))
    } else {
        scopes.join(", ")
    }
}

fn review_prompt(
    exchange: &Exchange,
    namespaces: &Namespaces,
    entries: &[odin_brain::learn::Entry],
) -> String {
    let scopes = scope_list(namespaces);
    let mut prompt = format!("Scopes: {scopes}\nEntries:\n");
    if entries.is_empty() {
        prompt.push_str("(none)\n");
    }
    for entry in entries {
        prompt.push_str(&format!(
            "id={} in {} ({}) {}{}\n",
            entry.id,
            entry.namespace,
            entry.kind.as_str(),
            entry
                .title
                .as_ref()
                .map(|title| format!("{title}: "))
                .unwrap_or_default(),
            clip(
                &entry.body.split_whitespace().collect::<Vec<_>>().join(" "),
                ENTRY_CHARS
            )
        ));
    }
    let who = if exchange.trigger == "task" {
        "Task"
    } else {
        "Colin"
    };
    prompt.push_str(&format!(
        "\nExchange ({} {}):\n{who}: {}\n{}: {}\n",
        exchange.trigger,
        exchange.session,
        clip(&exchange.asked, EXCHANGE_CHARS),
        exchange.seat,
        clip(&exchange.answered, EXCHANGE_CHARS)
    ));
    prompt
}

fn review_endpoint(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1/chat/completions") {
        base.to_owned()
    } else {
        format!("{base}/v1/chat/completions")
    }
}

fn ask_lane(gateway: &str, lane: &str, seat: &SeatId, prompt: &str) -> Result<String, ReviewError> {
    let key = std::env::var(KEY_ENV).map_err(|_| ReviewError::NoKey)?;
    let client = crate::http_pool::default_redirect()
        .map_err(|error| ReviewError::Lane(error.to_string()))?;
    let response = client
        .post(gateway)
        .timeout(std::time::Duration::from_secs(120))
        .bearer_auth(key)
        .header("x-litellm-tags", format!("seat:{seat},brain-review"))
        .json(&json!({
            "model": lane,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": REVIEW_SYSTEM},
                {"role": "user", "content": prompt},
            ],
        }))
        .send()
        .map_err(|error| ReviewError::Lane(error.to_string()))?;
    let status = response.status();
    let body: Value = response
        .json()
        .map_err(|error| ReviewError::Lane(format!("{status}: {error}")))?;
    if !status.is_success() {
        return Err(ReviewError::Lane(format!("{status}: {body}")));
    }
    body.pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ReviewError::Lane(format!("no answer in {body}")))
}

/// The edit list in a lane answer, tolerating a fenced or prefaced object.
fn parse_edits(answer: &str) -> Result<Vec<Edit>, ReviewError> {
    let (Some(start), Some(end)) = (answer.find('{'), answer.rfind('}')) else {
        return Err(ReviewError::Answer(clip(answer, 200)));
    };
    serde_json::from_str::<Edits>(&answer[start..=end])
        .map(|edits| edits.edits)
        .map_err(|error| ReviewError::Answer(format!("{error}: {}", clip(answer, 200))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_brain::learn::{EditAction, EditScope, EntryKind};

    fn runtime(root: &std::path::Path) -> Arc<super::super::HermesRuntime> {
        runtime_with_purchase(root, odin_ledger::Ledger::open_in_memory().unwrap())
    }

    fn runtime_with_purchase(
        root: &std::path::Path,
        purchase: odin_ledger::Ledger,
    ) -> Arc<super::super::HermesRuntime> {
        use odin_ledger::Ledger;
        super::super::HermesRuntime::open(
            crate::config::HermesSettings::new(root.join("hermes"), None, None, None, vec![])
                .unwrap(),
            super::super::HermesLedgers {
                conversation: Ledger::open_in_memory().unwrap(),
                adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
                purchase: Arc::new(std::sync::Mutex::new(purchase)),
            },
            &std::collections::BTreeMap::new(),
            None,
            8192,
            std::collections::BTreeMap::new(),
            None,
        )
        .unwrap()
    }

    fn lifecycle(runtime: &super::super::HermesRuntime) -> Vec<odin_ledger::audit::AuditEvent> {
        runtime
            .purchase_ledger
            .lock()
            .unwrap()
            .audit_events_after(0, 64)
            .unwrap()
    }

    fn task_exchange() -> Exchange {
        Exchange {
            seat: SeatId::new("gungnir").unwrap(),
            session: "exact-child".into(),
            parent_session: Some("exact-parent".into()),
            project: None,
            trigger: "task",
            turn_keys: Vec::new(),
            sequence: Some(54),
            asked: "task".into(),
            answered: "result".into(),
        }
    }

    #[test]
    fn task_capture_receipt_survives_reopen_without_repeating_work() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("authority.sqlite");
        let exchange = task_exchange();
        let first = runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        let calls = std::cell::Cell::new(0);
        first
            .review_task_completion_with(&exchange, || {
                calls.set(calls.get() + 1);
                Ok(1)
            })
            .unwrap();
        first
            .review_task_completion_with(&exchange, || panic!("duplicate work"))
            .unwrap();
        drop(first);
        let reopened =
            runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        reopened
            .review_task_completion_with(&exchange, || panic!("reopened work"))
            .unwrap();
        assert_eq!(calls.get(), 1);
        for distinct in [
            Exchange {
                sequence: Some(55),
                ..exchange.clone()
            },
            Exchange {
                session: "foreign-child".into(),
                ..exchange.clone()
            },
            Exchange {
                parent_session: Some("foreign-parent".into()),
                ..exchange.clone()
            },
        ] {
            reopened
                .review_task_completion_with(&distinct, || {
                    calls.set(calls.get() + 1);
                    Ok(0)
                })
                .unwrap();
        }
        assert_eq!(calls.get(), 4);
    }

    #[test]
    fn task_capture_retries_only_proven_pre_effect_failures() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("authority.sqlite");
        let first = runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        let exchange = task_exchange();
        assert!(matches!(
            first.review_task_completion_with(&exchange, || Err(ReviewError::NoKey)),
            Err(TaskReviewError::Dependency(_))
        ));
        drop(first);
        let runtime = runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        runtime
            .review_task_completion_with(&exchange, || Ok(0))
            .unwrap();
        runtime
            .review_task_completion_with(&exchange, || panic!("already captured"))
            .unwrap();
    }

    #[test]
    fn task_capture_does_not_repeat_work_after_a_post_commit_audit_failure() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("authority.sqlite");
        let exchange = task_exchange();
        let first = runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        assert!(matches!(
            first.review_task_completion_with(&exchange, || {
                Err(ReviewError::Journal(
                    "a committed change has no audit receipt".into(),
                ))
            }),
            Err(TaskReviewError::Uncertain)
        ));
        drop(first);
        let reopened =
            runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        assert!(matches!(
            reopened.review_task_completion_with(&exchange, || panic!("must not repeat a commit")),
            Err(TaskReviewError::Uncertain)
        ));
        let events = lifecycle(&reopened);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, REVIEW_PENDING_AUDIT_KIND);
        assert_eq!(events[0].payload["status"], "pending");
    }

    #[test]
    fn task_capture_pending_reopen_and_legacy_failure_refuse_replay() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("authority.sqlite");
        let first = runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        let exchange = task_exchange();
        let mut pending = first
            .register_review(
                exchange.session.clone(),
                "task",
                exchange.sequence,
                Vec::new(),
                exchange.parent_session.clone(),
            )
            .unwrap();
        // Simulate a process loss without manufacturing a terminal receipt.
        pending.completed = true;
        drop(pending);
        drop(first);
        let reopened =
            runtime_with_purchase(root.path(), odin_ledger::Ledger::open(&path).unwrap());
        assert!(matches!(
            reopened.review_task_completion_with(&exchange, || panic!("uncertain effects")),
            Err(TaskReviewError::Uncertain)
        ));
        let events = lifecycle(&reopened);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, REVIEW_PENDING_AUDIT_KIND);
        assert_eq!(events[0].payload["status"], "pending");
        let other = Exchange {
            sequence: Some(55),
            ..exchange
        };
        reopened
            .register_review(
                other.session.clone(),
                "task",
                other.sequence,
                Vec::new(),
                other.parent_session.clone(),
            )
            .unwrap()
            .complete(ReviewOutcome::Failed("possibly partially applied".into()));
        assert!(matches!(
            reopened.review_task_completion_with(&other, || panic!("legacy uncertain effects")),
            Err(TaskReviewError::Uncertain)
        ));
    }

    #[test]
    fn task_capture_does_not_accept_foreign_trigger_receipts() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let exchange = task_exchange();
        runtime
            .register_review(
                exchange.session.clone(),
                "turn",
                exchange.sequence,
                Vec::new(),
                exchange.parent_session.clone(),
            )
            .unwrap()
            .complete(ReviewOutcome::Settled(1));
        let ran = std::cell::Cell::new(false);
        runtime
            .review_task_completion_with(&exchange, || {
                ran.set(true);
                Ok(0)
            })
            .unwrap();
        assert!(ran.get());
    }

    #[tokio::test]
    async fn accepted_slow_review_stays_pending_until_its_last_write_returns() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let review = runtime
            .register_review(
                "slow-session".into(),
                "turn",
                Some(7),
                vec!["discord:v1:1:2".into()],
                None,
            )
            .unwrap();
        let id = review.id.clone();
        let pending = lifecycle(&runtime);
        assert_eq!(
            pending.len(),
            1,
            "acceptance precedes even the async lookup spawn"
        );
        assert_eq!(pending[0].kind, REVIEW_PENDING_AUDIT_KIND);
        assert_eq!(pending[0].payload["turnKeys"], json!(["discord:v1:1:2"]));

        let (resolve, resolved) = tokio::sync::oneshot::channel();
        let (started, writing) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let state =
            BrainState::open(root.path().join("memories"), root.path().join("brain.git")).unwrap();
        let writer = Arc::clone(&runtime);
        let worker = tokio::spawn(async move {
            resolved.await.unwrap();
            tokio::task::spawn_blocking(move || {
                review.run(|| {
                    started.send(()).unwrap();
                    blocked.recv().unwrap();
                    let (learned, refused) = writer.learn(
                        ReviewMutation::acquire(),
                        &state,
                        &Namespaces {
                            colin: None,
                            seat: "gungnir".into(),
                            project: None,
                            writable: vec!["gungnir".into()],
                        },
                        &[Edit {
                            action: EditAction::Add,
                            kind: EntryKind::Memory,
                            scope: EditScope::Seat,
                            id: None,
                            title: "Slow fixture".into(),
                            content: "A causal fixture fact".into(),
                            evidence: "the completed exchange".into(),
                        }],
                        &Provenance {
                            seat: "gungnir".into(),
                            session: "slow-session".into(),
                            trigger: "turn".into(),
                        },
                        None,
                    )?;
                    assert!(refused.is_empty());
                    Ok(learned.len())
                })
            })
            .await
            .unwrap();
        });
        assert_eq!(
            lifecycle(&runtime).len(),
            1,
            "cleanup cannot finish during exchange lookup"
        );
        resolve.send(()).unwrap();
        writing.await.unwrap();
        assert_eq!(
            lifecycle(&runtime).len(),
            1,
            "cleanup cannot finish during review writes"
        );

        // An unrelated review may finish without discharging the captured one.
        runtime
            .register_review("other".into(), "turn", None, Vec::new(), None)
            .unwrap()
            .complete(ReviewOutcome::Skipped("unrelated".into()));
        assert!(!lifecycle(&runtime)
            .iter()
            .any(|event| event.kind == REVIEW_COMPLETED_AUDIT_KIND
                && event.payload["reviewId"] == id));
        release.send(()).unwrap();
        worker.await.unwrap();
        let completed: Vec<_> = lifecycle(&runtime)
            .into_iter()
            .filter(|event| {
                event.kind == REVIEW_COMPLETED_AUDIT_KIND && event.payload["reviewId"] == id
            })
            .collect();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].payload["status"], "settled");
        assert_eq!(completed[0].payload["applied"], 1);
        let events = lifecycle(&runtime);
        let learned = events
            .iter()
            .find(|event| event.kind == LEARNED_AUDIT_KIND)
            .unwrap();
        assert!(
            learned.sequence < completed[0].sequence,
            "commit proof precedes completion"
        );
        let page = learned.payload["page"].as_str().unwrap();
        assert!(root.path().join("memories").join(page).is_file());
    }

    #[test]
    fn failed_and_cancelled_reviews_have_one_failed_terminal_not_settled() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        runtime
            .register_review(
                "failure".into(),
                "task",
                Some(9),
                Vec::new(),
                Some("parent".into()),
            )
            .unwrap()
            .run(|| Err(ReviewError::Lane("gateway unavailable".into())));
        drop(
            runtime
                .register_review("cancelled".into(), "result", Some(11), Vec::new(), None)
                .unwrap(),
        );
        let completed: Vec<_> = lifecycle(&runtime)
            .into_iter()
            .filter(|event| event.kind == REVIEW_COMPLETED_AUDIT_KIND)
            .collect();
        assert_eq!(completed.len(), 2);
        assert!(completed
            .iter()
            .all(|event| event.payload["status"] == "failed"));
        assert_eq!(completed[0].payload["parentSession"], "parent");
        assert!(completed[0].payload["reason"]
            .as_str()
            .unwrap()
            .contains("gateway unavailable"));
        assert!(completed[1].payload["reason"]
            .as_str()
            .unwrap()
            .contains("dropped"));
    }

    #[test]
    fn absent_executor_and_lane_are_explicitly_skipped() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let exchange = Exchange {
            seat: SeatId::new("gungnir").unwrap(),
            session: "no-executor".into(),
            parent_session: None,
            project: None,
            trigger: "turn",
            turn_keys: Vec::new(),
            sequence: None,
            asked: "ask".into(),
            answered: "answer".into(),
        };
        runtime.review_after(exchange.clone());
        runtime
            .register_review("no-lane".into(), "turn", None, Vec::new(), None)
            .unwrap()
            .run(|| runtime.review(&exchange));
        let completed: Vec<_> = lifecycle(&runtime)
            .into_iter()
            .filter(|event| event.kind == REVIEW_COMPLETED_AUDIT_KIND)
            .collect();
        assert_eq!(completed.len(), 2);
        assert!(completed
            .iter()
            .all(|event| event.payload["status"] == "skipped"));
    }

    #[test]
    fn a_review_runs_only_on_the_seat_declared_lane() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let seat = SeatId::new("gungnir").unwrap();
        let exchange = Exchange {
            seat: seat.clone(),
            session: "session-1".to_owned(),
            parent_session: None,
            project: None,
            turn_keys: Vec::new(),
            sequence: None,
            trigger: "turn",
            asked: "what is the test command?".to_owned(),
            answered: "cargo nextest run".to_owned(),
        };
        assert!(matches!(
            runtime.review(&exchange),
            Err(ReviewError::NoLane(undeclared)) if undeclared == seat
        ));
        runtime.set_review_lanes(std::collections::BTreeMap::from([(
            seat,
            "zai-glm".to_owned(),
        )]));
        runtime.set_review_gateway("http://gateway.example".to_owned());
        assert!(
            matches!(runtime.review(&exchange), Err(ReviewError::NoVault)),
            "a declared lane passes the lane gate"
        );
    }

    #[test]
    fn a_learned_commit_is_journaled_once_in_the_authority_ledger() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let provenance = Provenance {
            seat: "sinmara".to_owned(),
            session: "session-2".to_owned(),
            trigger: "turn".to_owned(),
        };
        let learned = Learned {
            action: EditAction::Add,
            kind: EntryKind::Memory,
            page: "colin/memory-tea".to_owned(),
            commit: "0123456789abcdef".to_owned(),
        };
        runtime
            .journal_learned(&provenance, None, &learned)
            .unwrap();
        runtime
            .journal_learned(&provenance, None, &learned)
            .expect("journaling the same commit again keeps its one event");
        let events = runtime
            .purchase_ledger
            .lock()
            .unwrap()
            .audit_events_after(0, 16)
            .unwrap();
        let [event] = events.as_slice() else {
            panic!("exactly one audit row: {events:?}");
        };
        assert_eq!(event.kind, LEARNED_AUDIT_KIND);
        assert_eq!(
            event.scope.seat.as_ref().map(SeatId::as_str),
            Some("sinmara")
        );
    }

    #[test]
    fn a_fenced_answer_parses_and_prose_is_refused() {
        let edits = parse_edits(
            "```json\n{\"edits\":[{\"action\":\"add\",\"kind\":\"memory\",\"scope\":\"colin\",\
             \"title\":\"Coffee\",\"content\":\"Colin drinks it black\",\"evidence\":\"he said so\"}]}\n```",
        )
        .unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].action, EditAction::Add);
        assert_eq!(edits[0].kind, EntryKind::Memory);
        assert_eq!(edits[0].scope, EditScope::Colin);
        assert!(parse_edits("{\"edits\":[]}").unwrap().is_empty());
        assert!(matches!(
            parse_edits("I think nothing is worth keeping."),
            Err(ReviewError::Answer(_))
        ));
        assert!(matches!(
            parse_edits("{\"edits\":[{\"action\":\"delete\"}]}"),
            Err(ReviewError::Answer(_))
        ));
    }

    #[test]
    fn the_prompt_names_every_entry_and_both_sides() {
        let prompt = review_prompt(
            &Exchange {
                seat: SeatId::new("sinmara").unwrap(),
                session: "s1".to_owned(),
                parent_session: None,
                project: None,
                turn_keys: Vec::new(),
                sequence: None,
                trigger: "turn",
                asked: "I drink my coffee black".to_owned(),
                answered: "Noted.".to_owned(),
            },
            &Namespaces {
                colin: Some("colin".to_owned()),
                seat: "sinmara".to_owned(),
                project: None,
                writable: vec!["colin".to_owned(), "sinmara".to_owned()],
            },
            &[odin_brain::learn::Entry {
                namespace: "colin".to_owned(),
                id: "memory-tea".to_owned(),
                kind: EntryKind::Memory,
                title: Some("Tea".to_owned()),
                body: "Colin likes\ngreen tea".to_owned(),
            }],
        );
        assert!(prompt.contains("id=memory-tea in colin (memory) Tea: Colin likes green tea"));
        assert!(prompt.contains("Colin: I drink my coffee black\nsinmara: Noted."));
        assert!(
            prompt.starts_with("Scopes: colin, seat (this session has no project memory)\n"),
            "a session without project memory is never offered the project scope"
        );
    }

    #[test]
    fn review_namespaces_follow_declared_write_grants() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        let gungnir = SeatId::new("gungnir").unwrap();
        let namespaces = runtime.namespaces(&gungnir, None);
        assert!(namespaces.colin.is_none());
        assert!(!namespaces.grants("colin"));
        assert!(namespaces.grants("gungnir"));
        runtime.set_memory_grants(std::collections::BTreeMap::from([(
            SeatId::new("sinmara").unwrap(),
            super::super::MemoryGrant {
                own: true,
                profile: Some("colin".to_owned()),
            },
        )]));
        let namespaces = runtime.namespaces(&SeatId::new("sinmara").unwrap(), None);
        assert_eq!(namespaces.colin.as_deref(), Some("colin"));
        assert!(namespaces.grants("colin"));
        assert!(namespaces.grants("sinmara"));
    }

    #[test]
    fn a_seat_without_a_review_lane_skips_before_the_gateway() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        runtime
            .review_task_completion(task_exchange())
            .expect("no review lane is a skip, not a retryable gateway failure");
        let completed: Vec<_> = lifecycle(&runtime)
            .into_iter()
            .filter(|event| event.kind == REVIEW_COMPLETED_AUDIT_KIND)
            .collect();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].payload["status"], "skipped");
    }

    #[test]
    fn review_refuses_without_a_configured_gateway() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path());
        runtime.set_review_lanes(std::collections::BTreeMap::from([(
            SeatId::new("gungnir").unwrap(),
            "zai-glm".to_owned(),
        )]));
        let error = runtime.review(&task_exchange()).unwrap_err();
        assert!(matches!(error, ReviewError::NoGateway));
    }

    #[test]
    fn review_endpoint_appends_the_chat_completions_path() {
        assert_eq!(
            review_endpoint("http://127.0.0.1:4000"),
            "http://127.0.0.1:4000/v1/chat/completions"
        );
        assert_eq!(
            review_endpoint("http://gateway.example/v1/chat/completions/"),
            "http://gateway.example/v1/chat/completions"
        );
    }
}
