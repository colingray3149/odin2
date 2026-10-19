//! Initialize the conversation without gating daemon startup. Failures publish
//! an incident and retry the same idempotent open with capped backoff. Terminally
//! closed vehicles get one Critical incident and no retry or replacement.
//!
//! Settled outcomes park the pump because normal completion stops serving;
//! shutdown aborts it. Intent routes remain unset until initialization succeeds.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_domain::IncidentId;
use odin_hermes::conversation::InitializeError;
use odin_huginn::incidents::{
    IncidentProjection, IncidentSeverityView, IncidentStatusView, IncidentView,
};
use odin_huginn::read_model::MaterializedReadModel;
use serde_json::json;
use time::OffsetDateTime;

/// The retry cadence of the one lane: delays double from `initial` up to
/// the `max` cap and retries continue INDEFINITELY on that capped cadence;
/// `escalation_after` failed attempts publish the card's one escalation.
#[derive(Clone, Copy, Debug)]
pub(super) struct VehicleRetrySchedule {
    escalation_after: usize,
    initial: StdDuration,
    max: StdDuration,
}

impl VehicleRetrySchedule {
    /// The production cadence: doubling from 2s capped at 60s — the card
    /// escalates to the operator at attempt 8 (roughly three minutes in)
    /// while the capped lane keeps retrying, so capacity freed at ANY later
    /// moment is recovered without a daemon restart.
    pub(super) const fn production() -> Self {
        Self {
            escalation_after: 8,
            initial: StdDuration::from_secs(2),
            max: StdDuration::from_secs(60),
        }
    }

    /// The wait BEFORE a retry after `retry_index` failed attempts: the
    /// first retry waits `initial`, doubling per further failure, capped
    /// at `max`.
    fn delay(&self, retry_index: usize) -> StdDuration {
        let initial_ms = self.initial.as_millis() as u64;
        let doubled = initial_ms.saturating_mul(1u64 << retry_index.saturating_sub(1).min(16));
        let capped = doubled.min(self.max.as_millis() as u64);
        StdDuration::from_millis(capped.max(1))
    }

    /// Tests may use a shorter capped retry schedule than production.
    #[cfg(test)]
    pub(super) const fn new(
        escalation_after: usize,
        initial: StdDuration,
        max: StdDuration,
    ) -> Self {
        Self {
            escalation_after,
            initial,
            max,
        }
    }
}

/// No vehicle binding means the surface is disarmed and no pump is started.
pub(super) fn arm_vehicle_open_lane(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    vehicle: Option<super::hermes_routes::VehicleRouteBinding>,
    read_model: Arc<MaterializedReadModel>,
    schedule: VehicleRetrySchedule,
) {
    let Some(super::hermes_routes::VehicleRouteBinding { runtime, root }) = vehicle else {
        return;
    };
    pumps.spawn(async move {
        // Single-flight: this lane is the ONLY initialization caller, and
        // the root's own lock serializes it against prompts and decisions.
        let mut incident: Option<IncidentCard> = None;
        let mut attempt: usize = 0;
        let mut not_before = StdDuration::ZERO;
        loop {
            attempt += 1;
            if attempt > 1 {
                tokio::time::sleep(schedule.delay(attempt - 1).max(not_before)).await;
            }
            not_before = StdDuration::ZERO;
            match root.initialize().await {
                Ok(()) => {
                    runtime.set_approved_intent_route(root.clone());
                    runtime.set_owner_decision_route(root.clone());
                    // Drain waiting intents immediately through the shared reconcile path, without a new DM.
                    {
                        let runtime = Arc::clone(&runtime);
                        let drained = tokio::task::spawn_blocking(move || {
                            let gated = runtime.reconcile_gated_tasks();
                            let admitted = runtime.reconcile_admitted_intents();
                            (gated, admitted)
                        })
                        .await;
                        match drained {
                            Ok((Ok(g), Ok(a))) => {
                                if g + a > 0 {
                                    tracing::info!(
                                        "vehicle-ready drain settled {g} gated and {a} admitted intent(s) waiting for the route"
                                    );
                                }
                            }
                            error => tracing::error!(
                                "vehicle-ready intent drain failed: {error:?}"
                            ),
                        }
                    }
                    if let Some(incident) = &mut incident {
                        incident.resolve(observed_at());
                        incident.publish(&read_model);
                    }
                    tracing::info!(
                        "conversation vehicle {} is open; approved intents route",
                        root.conversation_id()
                    );
                    park().await;
                }
                Err(InitializeError::Stopping) => {
                    // Shutdown owns this lane: park quietly — the runtime
                    // is stopping, not failing, and no incident is due.
                    park().await;
                }
                Err(InitializeError::TerminalClosed { session }) => {
                    tracing::warn!(
                        "conversation vehicle {session} is terminally closed; the \
                         closed lifecycle stays final — publishing one incident and \
                         parking without retry"
                    );
                    publish_terminal_closed(&read_model, &session, observed_at());
                    park().await;
                }
                Err(InitializeError::SuccessorBackoff {
                    attempts,
                    retry_at_unix_ms,
                }) => {
                    // The transition reported it to the incident desk.
                    let now_ms = u64::try_from(observed_at().unix_timestamp_nanos() / 1_000_000)
                        .unwrap_or(0);
                    not_before = StdDuration::from_millis(retry_at_unix_ms.saturating_sub(now_ms));
                    tracing::warn!(
                        "conversation successor backoff conversation={} ended={attempts} \
                         retry_in_s={}",
                        root.conversation_id(),
                        not_before.as_secs()
                    );
                }
                Err(InitializeError::SuccessorExhausted { attempts }) => {
                    // The transition reported it to the incident desk.
                    tracing::warn!(
                        "conversation successor exhausted conversation={} ended={attempts}; \
                         parking without retry",
                        root.conversation_id()
                    );
                    park().await;
                }
                Err(InitializeError::Failed(cause)) => {
                    tracing::warn!(
                        "conversation vehicle open failed (attempt {attempt}) and \
                         stays nonfatal: {cause}"
                    );
                    match &mut incident {
                        None => {
                            incident = IncidentCard::open(&read_model, &cause, observed_at());
                        }
                        Some(card) => card.observe(&cause, observed_at()),
                    }
                    if attempt == schedule.escalation_after {
                        if let Some(card) = &mut incident {
                            card.escalate(attempt, observed_at());
                            card.publish(&read_model);
                        }
                    }
                }
            }
        }
    });
}

/// The lane's park: forever-pending at each await, never resolving back
/// into the serving select, cancellable by the owning shutdown's abort.
async fn park() -> ! {
    loop {
        std::future::pending::<()>().await;
    }
}

const NO_ACTION_REQUIRED: &str = "No operator action is required while the capped \
     retry lane runs; the card escalates if the failure persists past the \
     escalation window.";

const GOVERNED_RECOVERY_ACTION: &str = "Recovery capacity through the governed \
     online paths (a Restart, or a whole-session Abort of the dead tracked \
     sessions), or fix the indicated cause; the capped lane re-opens the same \
     durable identity without a daemon restart.";

/// The lane's ONE incident card, mutated in place: opened on the first
/// recoverable failure (revision 1, Open), re-observed WITHOUT a
/// publication on later failures (cause refresh only — never a card per
/// attempt), escalated exactly once past the escalation window, and
/// resolved in place on the governed recovery. Bounded history: at most
/// two publications after the first, one card id for the lane lifetime.
struct IncidentCard {
    view: IncidentView,
}

impl IncidentCard {
    /// Mints and publishes the Open card; `None` when the identity could
    /// not even be minted (the alert failure is logged and the retry lane
    /// itself is unaffected).
    fn open(
        read_model: &Arc<MaterializedReadModel>,
        cause: &str,
        at: OffsetDateTime,
    ) -> Option<Self> {
        let incident_id = match mint_incident_id(at) {
            Ok(incident_id) => incident_id,
            Err(error) => {
                tracing::error!("the vehicle-open Huginn incident could not be published: {error}");
                return None;
            }
        };
        let view = IncidentView {
            incident_id,
            run_id: None,
            severity: IncidentSeverityView::Error,
            confidence_micros: 1_000_000,
            deviation: format!(
                "The conversation vehicle open failed and stays nonfatal: {cause}. \
                 A capped-backoff lane is re-running the same governed open while \
                 every other daemon surface keeps serving."
            ),
            failure_signature: "odind.conversation.vehicle.open".to_owned(),
            expected_state: json!({ "vehicle": "open" }),
            observed_state: json!({ "cause": cause }),
            affected_objects: vec!["hermes.conversation.vehicle".to_owned()],
            evidence_refs: vec!["odind:vehicle-open-lane".to_owned()],
            allowed_capabilities: Vec::new(),
            attempt_ids: Vec::new(),
            recommended_next_action: NO_ACTION_REQUIRED.to_owned(),
            escalation_target: "seat:operator".to_owned(),
            first_observed_at: at,
            last_observed_at: at,
            last_useful_progress_at: None,
            status: IncidentStatusView::Open,
            revision: 1,
        };
        publish(read_model, &view);
        Some(Self { view })
    }

    /// Later failures refresh the observed cause in place: no publication,
    /// no history growth.
    fn observe(&mut self, cause: &str, at: OffsetDateTime) {
        self.view.observed_state["cause"] = json!(cause);
        self.view.last_observed_at = at;
    }

    /// The one escalation past the window: same card id, revision bump.
    fn escalate(&mut self, attempts: usize, at: OffsetDateTime) {
        self.view.status = IncidentStatusView::Escalated;
        self.view.revision += 1;
        self.view.observed_state["attempts"] = json!(attempts);
        self.view.last_observed_at = at;
        self.view.deviation = format!(
            "The conversation vehicle open keeps failing past its escalation window \
             ({attempts} attempts) and stays unavailable: {}. The vehicle's \
             unavailability is explicit; the capped lane keeps retrying and every \
             other daemon surface keeps serving.",
            self.view.observed_state["cause"]
                .as_str()
                .unwrap_or_default()
        );
        self.view.recommended_next_action = GOVERNED_RECOVERY_ACTION.to_owned();
    }

    /// The governed recovery: same card id, resolved in place.
    fn resolve(&mut self, at: OffsetDateTime) {
        self.view.status = IncidentStatusView::Resolved;
        self.view.revision += 1;
        self.view.last_observed_at = at;
        self.view.last_useful_progress_at = Some(at);
        self.view.observed_state["vehicle"] = json!("open");
        self.view.deviation = format!(
            "The conversation vehicle open recovered through the capped retry lane: \
             the same governed open now holds the durable identity. Latest cause: {}.",
            self.view.observed_state["cause"]
                .as_str()
                .unwrap_or_default()
        );
        self.view.recommended_next_action =
            "None — the vehicle recovered in place on the same governed identity.".to_owned();
    }

    fn publish(&self, read_model: &Arc<MaterializedReadModel>) {
        publish(read_model, &self.view);
    }
}

/// The typed failures of the vehicle-open lane alert.
#[derive(Debug, thiserror::Error)]
enum VehicleIncidentError {
    #[error("the vehicle-open incident identity is invalid: {0}")]
    IncidentIdentity(#[from] odin_domain::DomainError),
    #[error("the incident projection refused the vehicle-open card: {0}")]
    Projection(#[from] odin_domain::huginn::HuginnProtocolError),
}

/// The wall-clock milliseconds the shared identity mints bind (`now_ms`).
fn unix_ms(at: OffsetDateTime) -> u64 {
    let millis = at.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis.max(0)).unwrap_or(0)
}

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn mint_incident_id(at: OffsetDateTime) -> Result<IncidentId, VehicleIncidentError> {
    Ok(IncidentId::from_parts(
        "incident",
        unix_ms(at),
        uuid::Uuid::new_v4(),
    )?)
}

fn publish(read_model: &Arc<MaterializedReadModel>, view: &IncidentView) {
    if let Err(error) =
        IncidentProjection::new(Arc::clone(read_model)).publish(view.clone(), [], [])
    {
        tracing::error!("the vehicle-open Huginn incident could not be published: {error}");
    }
}

/// Publishes the terminal-closure card: a fresh identity (a terminal card
/// is never reopened), Critical severity, one publish, no retry. A mint
/// or projection failure is logged, never fatal to the parked lane.
fn publish_terminal_closed(
    read_model: &Arc<MaterializedReadModel>,
    session: &str,
    at: OffsetDateTime,
) {
    let incident_id = match mint_incident_id(at) {
        Ok(incident_id) => incident_id,
        Err(error) => {
            tracing::error!(
                "the vehicle terminal-closure Huginn incident could not be published: {error}"
            );
            return;
        }
    };
    let view = IncidentView {
        incident_id,
        run_id: None,
        severity: IncidentSeverityView::Critical,
        confidence_micros: 1_000_000,
        deviation: format!(
            "The conversation vehicle {session} is terminally closed; the closed \
             lifecycle stays final. The vehicle-open lane will never reopen or \
             replace the identity, and the conversation surface stays down while \
             every other daemon surface keeps serving."
        ),
        failure_signature: "odind.conversation.vehicle.terminal-closed".to_owned(),
        expected_state: json!({ "vehicle": "open" }),
        observed_state: json!({ "session": session, "retry": "none" }),
        affected_objects: vec!["hermes.conversation.vehicle".to_owned()],
        evidence_refs: vec!["odind:vehicle-open-lane".to_owned()],
        allowed_capabilities: Vec::new(),
        attempt_ids: Vec::new(),
        recommended_next_action: "The closed conversation identity is final; if a \
             replacement conversation is wanted, it is a declared operator \
             decision, not a lane retry. Every other surface keeps serving."
            .to_owned(),
        escalation_target: "seat:operator".to_owned(),
        first_observed_at: at,
        last_observed_at: at,
        last_useful_progress_at: None,
        status: IncidentStatusView::Open,
        revision: 1,
    };
    publish(read_model, &view);
}

#[cfg(test)]
#[path = "../tests/vehicle_open.rs"]
pub(crate) mod tests;
