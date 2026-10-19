//! The incident desk: one place every source — a seat's
//! `incident.raise`, the monitoring kernel, a routine — raises a typed
//! incident. Raising publishes the Huginn incident card, pages Colin's
//! phone for an error or worse (when a sink is declared), and wakes the
//! conversation once for a warning or worse, which tells him only what he
//! needs to know. Each leg's failure is
//! logged and reported back; none is swallowed and none blocks the others.
//!
//! A repeat of an open incident (same signature, seen within the coalescing
//! window, no higher severity) is coalesced into it: the card's count and
//! last-seen move, but Colin's phone and the conversation are not alerted
//! again until the incident clears or escalates.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use odin_domain::IncidentId;
use odin_huginn::incidents::{
    IncidentProjection, IncidentSeverityView, IncidentStatusView, IncidentView,
};
use odin_huginn::read_model::MaterializedReadModel;
use serde_json::json;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub(crate) struct RaisedIncident {
    /// Who raised it: `seat:<seat>`, `monitor:<profile>/<watchdog>`,
    /// `routine:<id>` — names the source in the card and the logs.
    pub source: String,
    pub severity: IncidentSeverityView,
    /// One line: what happened.
    pub summary: String,
    /// Bounded detail: what was observed and what was expected.
    pub detail: String,
    /// The objects it concerns (a pod, a run, a seat).
    pub affected: Vec<String>,
    /// A stable signature: repeated raises of one condition share it.
    pub signature: String,
}

/// What raising did, leg by leg.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IncidentReceipt {
    pub incident_id: String,
    pub published: bool,
    pub phone_alerted: bool,
    pub conversation_woken: bool,
    /// A repeat folded into the open incident of its signature: nobody is
    /// alerted again.
    pub coalesced: bool,
    /// How many raises the incident has absorbed, this one included.
    pub count: u32,
    /// Each leg that failed, with its reason.
    pub failures: Vec<String>,
}

/// How long an open incident absorbs repeats after it was last seen; a
/// condition that comes back later is news again.
pub(crate) const COALESCE_WINDOW: time::Duration = time::Duration::minutes(30);

/// One open incident, by signature.
#[derive(Clone, Debug)]
struct OpenIncident {
    view: IncidentView,
    count: u32,
}

fn severity_rank(severity: IncidentSeverityView) -> u8 {
    match severity {
        IncidentSeverityView::Info => 0,
        IncidentSeverityView::Warning => 1,
        IncidentSeverityView::Error => 2,
        IncidentSeverityView::Critical => 3,
    }
}

pub(crate) struct IncidentDesk {
    read_model: Arc<MaterializedReadModel>,
    runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    phone_url: Option<String>,
    open: Mutex<HashMap<String, OpenIncident>>,
}

impl IncidentDesk {
    pub(crate) fn new(
        read_model: Arc<MaterializedReadModel>,
        runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
        phone_url: Option<String>,
    ) -> Self {
        Self {
            read_model,
            runtime,
            phone_url,
            open: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn raise(&self, incident: RaisedIncident) -> IncidentReceipt {
        self.raise_at(incident, OffsetDateTime::now_utc())
    }

    /// Folds a repeat into the open incident of its signature, when there is
    /// one seen within the window and the repeat does not escalate it.
    fn coalesce(&self, incident: &RaisedIncident, at: OffsetDateTime) -> Option<IncidentReceipt> {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = open.get_mut(&incident.signature)?;
        if at - entry.view.last_observed_at > COALESCE_WINDOW
            || severity_rank(incident.severity) > severity_rank(entry.view.severity)
        {
            return None;
        }
        entry.count = entry.count.saturating_add(1);
        entry.view.revision += 1;
        entry.view.last_observed_at = at.max(entry.view.first_observed_at);
        entry.view.observed_state = json!({
            "detail": incident.detail,
            "source": incident.source,
            "count": entry.count,
            "latest": incident.summary,
        });
        let view = entry.view.clone();
        let count = entry.count;
        drop(open);
        let mut failures = Vec::new();
        let published = match IncidentProjection::new(Arc::clone(&self.read_model)).publish(
            view.clone(),
            [],
            [],
        ) {
            Ok(_) => true,
            Err(error) => {
                failures.push(format!("huginn: {error}"));
                false
            }
        };
        tracing::info!(
            "incident coalesced id={} source={} signature={} count={count} \
             published={published} failures={failures:?}",
            view.incident_id,
            incident.source,
            incident.signature
        );
        Some(IncidentReceipt {
            incident_id: view.incident_id.to_string(),
            published,
            phone_alerted: false,
            conversation_woken: false,
            coalesced: true,
            count,
            failures,
        })
    }

    /// The condition behind `signature` no longer holds (or its source is
    /// gone): the open incident is resolved, and the next raise is news.
    pub(crate) fn clear(&self, signature: &str, reason: &str) {
        let Some(mut entry) = self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(signature)
        else {
            return;
        };
        let at = OffsetDateTime::now_utc().max(entry.view.last_observed_at);
        entry.view.revision += 1;
        entry.view.status = IncidentStatusView::Resolved;
        entry.view.last_observed_at = at;
        let published = IncidentProjection::new(Arc::clone(&self.read_model))
            .publish(entry.view.clone(), [], [])
            .map_err(|error| error.to_string());
        tracing::info!(
            "incident cleared id={} signature={signature} count={} reason={reason}              published={published:?}",
            entry.view.incident_id, entry.count
        );
    }

    /// Re-publishes a condition that is still true but was already
    /// announced (a daemon restart forgot its card): the card returns to
    /// Huginn with no phone alert, no conversation wake and no routine.
    pub(crate) fn restate(&self, incident: RaisedIncident) -> Option<IncidentReceipt> {
        let open = self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&incident.signature);
        (!open).then(|| self.raise_with(incident, OffsetDateTime::now_utc(), false))
    }

    fn raise_at(&self, incident: RaisedIncident, at: OffsetDateTime) -> IncidentReceipt {
        self.raise_with(incident, at, true)
    }

    fn raise_with(
        &self,
        incident: RaisedIncident,
        at: OffsetDateTime,
        announce: bool,
    ) -> IncidentReceipt {
        if let Some(receipt) = self.coalesce(&incident, at) {
            return receipt;
        }
        let millis = u64::try_from((at.unix_timestamp_nanos() / 1_000_000).max(0)).unwrap_or(0);
        let mut failures = Vec::new();
        let incident_id = match IncidentId::from_parts("incident", millis, uuid::Uuid::new_v4()) {
            Ok(id) => id,
            Err(error) => {
                let reason = format!("incident identity: {error}");
                tracing::error!(
                    "incident source={} signature={} not raised: {reason}",
                    incident.source,
                    incident.signature
                );
                return IncidentReceipt {
                    incident_id: String::new(),
                    published: false,
                    phone_alerted: false,
                    conversation_woken: false,
                    coalesced: false,
                    count: 1,
                    failures: vec![reason],
                };
            }
        };
        let view = IncidentView {
            incident_id: incident_id.clone(),
            run_id: None,
            severity: incident.severity,
            confidence_micros: 1_000_000,
            deviation: incident.summary.clone(),
            failure_signature: incident.signature.clone(),
            expected_state: json!({}),
            observed_state: json!({ "detail": incident.detail, "source": incident.source }),
            affected_objects: incident.affected.clone(),
            evidence_refs: vec![incident.source.clone()],
            allowed_capabilities: Vec::new(),
            attempt_ids: Vec::new(),
            recommended_next_action: "Sinmara tells Colin; the raising source acts within its \
                                      declared capabilities."
                .to_owned(),
            escalation_target: "seat:conversation".to_owned(),
            first_observed_at: at,
            last_observed_at: at,
            last_useful_progress_at: None,
            status: IncidentStatusView::Open,
            revision: 1,
        };
        // Escalating an open incident keeps its identity and history.
        let view = match self
            .open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&incident.signature)
            .filter(|open| at - open.view.last_observed_at <= COALESCE_WINDOW)
        {
            Some(open) => IncidentView {
                incident_id: open.view.incident_id.clone(),
                first_observed_at: open.view.first_observed_at,
                revision: open.view.revision + 1,
                status: IncidentStatusView::Escalated,
                ..view
            },
            None => view,
        };
        let incident_id = view.incident_id.clone();
        let count = {
            let mut open = self
                .open
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let count = open
                .get(&incident.signature)
                .filter(|open| open.view.incident_id == incident_id)
                .map_or(1, |open| open.count.saturating_add(1));
            open.insert(
                incident.signature.clone(),
                OpenIncident {
                    view: view.clone(),
                    count,
                },
            );
            count
        };
        let published =
            match IncidentProjection::new(Arc::clone(&self.read_model)).publish(view, [], []) {
                Ok(_) => true,
                Err(error) => {
                    failures.push(format!("huginn: {error}"));
                    false
                }
            };
        let alerting = announce
            && matches!(
                incident.severity,
                IncidentSeverityView::Warning
                    | IncidentSeverityView::Error
                    | IncidentSeverityView::Critical
            );
        // Only Error and Critical page the phone; warnings use the conversation.
        let paging = announce
            && matches!(
                incident.severity,
                IncidentSeverityView::Error | IncidentSeverityView::Critical
            );
        let phone_alerted = match (&self.phone_url, paging) {
            (Some(url), true) => match phone_alert(url, &incident) {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("phone: {error}"));
                    false
                }
            },
            _ => false,
        };
        // Info stays in Huginn; warning and above reaches Colin.
        let conversation_woken = match (&self.runtime, alerting) {
            (Some(runtime), true) => {
                let text = format!(
                    "Incident ({:?}) raised by {}: {}\n{}\nCheck the current state with your governed \
                     reads first. If Colin needs to know or act, tell him in one plain sentence what \
                     happened and what (if anything) he should do; otherwise answer exactly [quiet].",
                    incident.severity, incident.source, incident.summary, incident.detail
                );
                match runtime.wake_once(&format!("incident-{incident_id}"), &text) {
                    Ok(_) => true,
                    Err(error) => {
                        failures.push(format!("conversation: {error}"));
                        false
                    }
                }
            }
            _ => false,
        };
        // Routines that follow incidents.
        if alerting {
            if let Some(runtime) = &self.runtime {
                if let Err(error) = runtime.routine_event(
                    odin_registry::schema::RoutineEvent::Incident,
                    None,
                    incident_id.as_str(),
                    &format!("{} ({})", incident.summary, incident.source),
                    i64::try_from(millis).unwrap_or(i64::MAX),
                ) {
                    failures.push(format!("routines: {error}"));
                }
            }
        }
        tracing::info!(
            "incident id={incident_id} source={} severity={:?} signature={} \
             count={count} published={published} phone={phone_alerted} \
             woken={conversation_woken} failures={failures:?}",
            incident.source,
            incident.severity,
            incident.signature
        );
        IncidentReceipt {
            incident_id: incident_id.to_string(),
            published,
            phone_alerted,
            conversation_woken,
            coalesced: false,
            count,
            failures,
        }
    }
}
static PHONE_CLIENT: LazyLock<Result<reqwest::blocking::Client, String>> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .build()
        .map_err(|error| error.to_string())
});

/// One plain POST of the message to the declared ntfy topic, bounded.
fn phone_alert(url: &str, incident: &RaisedIncident) -> Result<(), String> {
    let client = PHONE_CLIENT.as_ref().map_err(Clone::clone)?;
    let response = client
        .post(url)
        .timeout(std::time::Duration::from_secs(5))
        .header("Title", format!("Odin {:?}", incident.severity))
        .body(format!("{} ({})", incident.summary, incident.source))
        .send()
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("{url} answered {}", response.status()))
    }
}

impl odin_hermes::runtime::incidents::IncidentRoute for IncidentDesk {
    fn raise(
        &self,
        seat: &odin_domain::SeatId,
        severity: &str,
        summary: String,
        detail: String,
        affected: Vec<String>,
    ) -> Result<serde_json::Value, String> {
        let severity = match severity {
            "info" => IncidentSeverityView::Info,
            "warning" => IncidentSeverityView::Warning,
            "error" => IncidentSeverityView::Error,
            "critical" => IncidentSeverityView::Critical,
            other => {
                return Err(format!(
                    "severity {other:?} is not info|warning|error|critical"
                ))
            }
        };
        let signature = format!(
            "seat:{seat}:{}",
            summary.chars().take(80).collect::<String>()
        );
        let receipt = self.raise(RaisedIncident {
            source: format!("seat:{seat}"),
            severity,
            summary,
            detail,
            affected,
            signature,
        });
        serde_json::to_value(receipt).map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desk() -> IncidentDesk {
        IncidentDesk::new(
            Arc::new(MaterializedReadModel::new(1024, OffsetDateTime::now_utc())),
            None,
            None,
        )
    }

    /// A closed local port records attempted pushes as failures.
    #[test]
    fn only_an_error_or_worse_pages_the_phone() {
        let desk = IncidentDesk::new(
            Arc::new(MaterializedReadModel::new(1024, OffsetDateTime::now_utc())),
            None,
            Some("http://127.0.0.1:9/odin-incidents".to_owned()),
        );
        let warning = desk.raise_at(
            watchdog(IncidentSeverityView::Warning, 0.02),
            OffsetDateTime::now_utc(),
        );
        assert!(
            !warning.phone_alerted && warning.failures.iter().all(|f| !f.starts_with("phone")),
            "a warning is not pushed: {:?}",
            warning.failures
        );
        let error = desk.raise_at(
            RaisedIncident {
                signature: "watchdog:odin-6df1:diverged".to_owned(),
                ..watchdog(IncidentSeverityView::Error, 9.0)
            },
            OffsetDateTime::now_utc(),
        );
        assert!(
            error.failures.iter().any(|f| f.starts_with("phone")),
            "an error is pushed (the closed sink refuses it): {:?}",
            error.failures
        );
    }

    /// adversarial d12: a restart forgot the exhausted-successor card while
    /// minting stays stopped; restating it returns the card without paging
    /// the phone again, and only while no card of that signature is open.
    #[test]
    fn a_restated_incident_returns_its_card_without_paging() {
        let desk = IncidentDesk::new(
            Arc::new(MaterializedReadModel::new(1024, OffsetDateTime::now_utc())),
            None,
            Some("http://127.0.0.1:9/odin-incidents".to_owned()),
        );
        let receipt = desk
            .restate(watchdog(IncidentSeverityView::Critical, 1.0))
            .expect("no card was open");
        assert!(receipt.published);
        assert!(
            !receipt.phone_alerted && receipt.failures.is_empty(),
            "{:?}",
            receipt.failures
        );
        assert!(desk
            .restate(watchdog(IncidentSeverityView::Critical, 1.0))
            .is_none());
        assert!(
            desk.raise_at(
                watchdog(IncidentSeverityView::Critical, 1.0),
                OffsetDateTime::now_utc()
            )
            .coalesced
        );
    }

    fn watchdog(severity: IncidentSeverityView, value: f64) -> RaisedIncident {
        RaisedIncident {
            source: "monitor:residual-watch/residual-high".to_owned(),
            severity,
            summary: format!("Pod odin-6df1: watchdog residual-high fired (now {value})"),
            detail: "held for 3 consecutive checks".to_owned(),
            affected: vec!["odin-6df1".to_owned()],
            signature: "watchdog:odin-6df1:residual-high".to_owned(),
        }
    }

    #[test]
    fn a_repeating_watchdog_is_one_incident_until_it_clears() {
        let desk = desk();
        let t0 = OffsetDateTime::now_utc();
        let first = desk.raise_at(watchdog(IncidentSeverityView::Warning, 0.0099), t0);
        assert!(!first.coalesced);
        assert_eq!(first.count, 1);
        for minute in 1..=5 {
            let again = desk.raise_at(
                watchdog(IncidentSeverityView::Warning, 0.0098),
                t0 + time::Duration::minutes(minute),
            );
            assert!(again.coalesced, "minute {minute} must not alert again");
            assert!(!again.phone_alerted && !again.conversation_woken);
            assert_eq!(again.incident_id, first.incident_id);
            assert_eq!(again.count, u32::try_from(minute).unwrap() + 1);
        }
        // Another condition is its own incident.
        let other = RaisedIncident {
            signature: "watchdog:odin-6df1:beat-negative".to_owned(),
            ..watchdog(IncidentSeverityView::Warning, 1.0)
        };
        assert!(!desk.raise_at(other, t0).coalesced);
        // Cleared, the same condition is news again.
        desk.clear(
            "watchdog:odin-6df1:residual-high",
            "the condition no longer holds",
        );
        let back = desk.raise_at(
            watchdog(IncidentSeverityView::Warning, 0.0097),
            t0 + time::Duration::minutes(6),
        );
        assert!(!back.coalesced);
        assert_ne!(back.incident_id, first.incident_id);
    }

    /// A worse severity escalates the open incident (alerts again, same
    /// identity); a repeat seen after the window is news again.
    #[test]
    fn escalation_and_a_stale_repeat_alert_again() {
        let desk = desk();
        let t0 = OffsetDateTime::now_utc();
        let first = desk.raise_at(watchdog(IncidentSeverityView::Warning, 0.01), t0);
        let worse = desk.raise_at(
            watchdog(IncidentSeverityView::Error, 0.02),
            t0 + time::Duration::minutes(1),
        );
        assert!(!worse.coalesced, "an escalation alerts");
        assert_eq!(worse.incident_id, first.incident_id);
        assert_eq!(worse.count, 2);
        let later = desk.raise_at(
            watchdog(IncidentSeverityView::Error, 0.02),
            t0 + time::Duration::minutes(1) + COALESCE_WINDOW + time::Duration::seconds(1),
        );
        assert!(!later.coalesced, "a repeat after the window is news");
        assert_ne!(later.incident_id, first.incident_id);
    }
}
