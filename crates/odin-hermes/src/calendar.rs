//! Calendar reads and approval-gated mutations through `calendar.*` capabilities.
//!
//! `calendar.propose` applies concrete mutations after host approval; no separate booking step exists.
//! Settlement verifies consumed approval without consuming it again. Uncertain dispatches are not retried.
//! Receipts contain event ids; the composition layer writes reminder and vault projections.

use std::sync::Arc;

use odin_domain::CapabilityId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::account::{
    fault_into_life, lease_into_life, settle_gated_effect, BatchFault, CredentialLeases,
    DurableEffect, EffectIdentity, EffectIntent, EffectRoute, HostConsumeProof, LifeError,
    ScopedCredentialLease, SettledEffect, TransportFault, MAX_ACCOUNT_CHARS,
};
use crate::jmap::{JmapCall, JmapExchange, JmapRequest, JMAP_CALENDARS, JMAP_CORE};

pub const CALENDAR_READ_OPERATION: &str = "calendar.read";
/// The registry capability id of the calendar propose operation. Its
/// gated effect is the booking; there is no separate booking id.
pub const CALENDAR_PROPOSE_OPERATION: &str = "calendar.propose";

pub const CALENDAR_PROPOSAL_TARGET_KIND: &str = "calendar.proposal";

pub const MAX_TITLE_CHARS: usize = 200;
pub const MAX_LOCATION_CHARS: usize = 512;
pub const MAX_EVENT_DESCRIPTION_CHARS: usize = 2000;
/// Most concrete events one `batchCreate` mutation may carry.
pub const MAX_BATCH_EVENTS: usize = 128;
pub const MAX_EVENT_ID_CHARS: usize = 128;
pub const MAX_TIMESTAMP_CHARS: usize = 64;
/// Widest read window accepted, in whole days.
pub const MAX_WINDOW_DAYS: i64 = 366;
/// Most events one window read may return.
pub const MAX_EVENTS: usize = 100;

const MSG_BOUND: &str = "the JMAP calendar response violated the declared output bounds";
const MSG_SHAPE: &str = "the JMAP calendar response was not the expected shape";
const MSG_METHOD_ERROR: &str = "the JMAP service reported a calendar method error";
const MSG_CONFIG: &str = "the JMAP calendar account configuration is incomplete";
const MSG_WINDOW: &str = "the calendar window is out of bounds";
const MSG_PROPOSAL_TIME: &str = "the proposal times are not RFC 3339 or not ordered";
const MSG_PROPOSAL_SPAN: &str = "the proposal span is out of bounds";
const MSG_PROPOSAL_SUBSECOND: &str = "the proposal span must be whole seconds";
const MSG_EVENT_ID: &str = "the event id is out of bounds";
const MSG_MUTATION_BATCH: &str = "the batch size is out of bounds";
const MSG_RECEIPT: &str = "the settled result is not a bounded mutation receipt";

/// Builds the capability id of one of this module's registry constants.
/// The ids are fixed above and known to satisfy the registry grammar.
fn capability(id: &'static str) -> CapabilityId {
    CapabilityId::new(id).expect("the reserved registry capability id is valid")
}

/// One calendar read window: half-open `[start, end)` in RFC 3339 UTC.
/// Bounds are enforced at the adapter boundary.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CalendarWindow {
    pub account: String,
    pub start: String,
    pub end: String,
}

impl CalendarWindow {
    fn validate(&self) -> Result<(OffsetDateTime, OffsetDateTime), LifeError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        let start = OffsetDateTime::parse(self.start.trim(), &Rfc3339)
            .map_err(|_| LifeError::InvalidInput(MSG_WINDOW))?;
        let end = OffsetDateTime::parse(self.end.trim(), &Rfc3339)
            .map_err(|_| LifeError::InvalidInput(MSG_WINDOW))?;
        if end <= start {
            return Err(LifeError::InvalidInput(MSG_WINDOW));
        }
        if (end - start).whole_days() > MAX_WINDOW_DAYS {
            return Err(LifeError::InvalidInput(MSG_WINDOW));
        }
        Ok((start, end))
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEventSummary {
    pub id: String,
    pub title: Option<String>,
    pub start: String,
    pub end: String,
    pub description: Option<String>,
}

/// One concrete calendar event a mutation creates. The content never
/// enters any status envelope — only ids and digests do.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CalendarEventDraft {
    pub title: String,
    pub start: String,
    pub end: String,
    pub location: Option<String>,
    pub description: Option<String>,
}

impl CalendarEventDraft {
    fn validate(&self) -> Result<(), LifeError> {
        let title = self.title.trim();
        if title.is_empty() || title.chars().count() > MAX_TITLE_CHARS {
            return Err(LifeError::InvalidInput("the title is out of bounds"));
        }
        validate_span(&self.start, &self.end)?;
        if let Some(location) = &self.location {
            if location.chars().count() > MAX_LOCATION_CHARS {
                return Err(LifeError::InvalidInput("the location is out of bounds"));
            }
        }
        if let Some(description) = &self.description {
            if description.chars().count() > MAX_EVENT_DESCRIPTION_CHARS {
                return Err(LifeError::InvalidInput("the description is out of bounds"));
            }
        }
        Ok(())
    }
}

/// Mutations address concrete events, never whole series or permanent deletion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CalendarMutation {
    Create(CalendarEventDraft),
    /// Reschedule one event to a new absolute window.
    Move {
        #[serde(rename = "eventId")]
        event_id: String,
        start: String,
        end: String,
    },
    /// Cancel one event (upstream status `cancelled`, never a
    /// destroy).
    Cancel {
        #[serde(rename = "eventId")]
        event_id: String,
    },
    /// Create at most [`MAX_BATCH_EVENTS`] concrete events in one
    /// upstream set call.
    BatchCreate {
        drafts: Vec<CalendarEventDraft>,
    },
}

/// Requires ordered RFC 3339 timestamps with whole-second duration within the read-window limit.
fn validate_span(start: &str, end: &str) -> Result<(), LifeError> {
    let start = OffsetDateTime::parse(start.trim(), &Rfc3339)
        .map_err(|_| LifeError::InvalidInput(MSG_PROPOSAL_TIME))?;
    let end = OffsetDateTime::parse(end.trim(), &Rfc3339)
        .map_err(|_| LifeError::InvalidInput(MSG_PROPOSAL_TIME))?;
    if end <= start {
        return Err(LifeError::InvalidInput(MSG_PROPOSAL_TIME));
    }
    let duration = end - start;
    if duration.whole_days() > MAX_WINDOW_DAYS {
        return Err(LifeError::InvalidInput(MSG_PROPOSAL_SPAN));
    }
    if duration.subsec_nanoseconds() != 0 {
        return Err(LifeError::InvalidInput(MSG_PROPOSAL_SUBSECOND));
    }
    Ok(())
}

fn validate_event_id(event_id: &str) -> Result<(), LifeError> {
    if event_id.trim().is_empty() || event_id.chars().count() > MAX_EVENT_ID_CHARS {
        return Err(LifeError::InvalidInput(MSG_EVENT_ID));
    }
    Ok(())
}

impl CalendarMutation {
    fn validate(&self) -> Result<(), LifeError> {
        match self {
            Self::Create(draft) => draft.validate(),
            Self::Move {
                event_id,
                start,
                end,
            } => {
                validate_event_id(event_id)?;
                validate_span(start, end)
            }
            Self::Cancel { event_id } => validate_event_id(event_id),
            Self::BatchCreate { drafts } => {
                if drafts.is_empty() || drafts.len() > MAX_BATCH_EVENTS {
                    return Err(LifeError::InvalidInput(MSG_MUTATION_BATCH));
                }
                for draft in drafts {
                    draft.validate()?;
                }
                Ok(())
            }
        }
    }
}

/// One gated mutation proposal. Booking it is the gated effect of
/// `calendar.propose`; the proposal content itself never enters any
/// status envelope — only ids and digests do.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CalendarProposal {
    pub account: String,
    pub mutation: CalendarMutation,
}

impl CalendarProposal {
    /// Rechecked during dispatch preflight, intent recording, and transport execution.
    pub(crate) fn validate(&self) -> Result<(), LifeError> {
        if self.account.trim().is_empty() || self.account.len() > MAX_ACCOUNT_CHARS {
            return Err(LifeError::InvalidInput(
                "the account selector is out of bounds",
            ));
        }
        self.mutation.validate()
    }
}

/// Applied event ids in upstream application order, excluding event contents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CalendarMutationReceipt {
    pub event_ids: Vec<String>,
}

impl CalendarMutationReceipt {
    fn validate(&self) -> Result<(), LifeError> {
        if self.event_ids.is_empty() || self.event_ids.len() > MAX_BATCH_EVENTS {
            return Err(LifeError::InvalidInput(MSG_RECEIPT));
        }
        for id in &self.event_ids {
            if id.is_empty() || id.chars().count() > MAX_EVENT_ID_CHARS {
                return Err(LifeError::InvalidInput(MSG_RECEIPT));
            }
        }
        Ok(())
    }

    /// Encodes ids as JSON because the durable effect engine stores one string per result.
    pub(crate) fn to_result_string(&self) -> Result<String, TransportFault> {
        self.validate()
            .map_err(|_| TransportFault::Protocol(MSG_RECEIPT))?;
        serde_json::to_string(&self.event_ids).map_err(|_| TransportFault::Protocol(MSG_RECEIPT))
    }

    /// Decodes the settled result document of a `calendar.propose`
    /// effect (fresh or replayed) into its typed receipt. Bounds are
    /// re-verified on read.
    pub fn from_settled(settled: &SettledEffect) -> Result<Self, LifeError> {
        let encoded = settled
            .result
            .get("eventIds")
            .and_then(Value::as_str)
            .ok_or(LifeError::InvalidInput(MSG_RECEIPT))?;
        let event_ids: Vec<String> =
            serde_json::from_str(encoded).map_err(|_| LifeError::InvalidInput(MSG_RECEIPT))?;
        let receipt = Self { event_ids };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// The account transport port. Implementations receive only the scoped
/// lease and report typed faults with static sanitized messages.
pub trait CalendarTransport: Send + Sync {
    /// Checks local account and credential prerequisites without contacting the provider or writing state.
    fn readiness(&self, account: &str) -> Result<(), TransportFault>;
    fn read_window(
        &self,
        lease: &ScopedCredentialLease,
        window: &CalendarWindow,
        now: OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, TransportFault>;
    /// Validates the entire batch before mutation and returns known applied ids on partial failure.
    /// A failure with an uncertain outcome must leave the durable effect in-doubt.
    fn apply(
        &self,
        lease: &ScopedCredentialLease,
        proposal: &CalendarProposal,
        now: OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault>;
}

/// Deployment facts of one JMAP calendar account, all rendered from
/// Nix/dotfiles configuration. No field has a default.
#[derive(Clone)]
pub struct JmapCalendarConfig {
    pub account_id: String,
    /// The calendar collection bookings create into.
    pub calendar_id: String,
    pub exchange: Arc<dyn JmapExchange>,
}

impl JmapCalendarConfig {
    fn validated(&self) -> Result<(), TransportFault> {
        for field in [self.account_id.as_str(), self.calendar_id.as_str()] {
            if field.trim().is_empty() {
                return Err(TransportFault::Protocol(MSG_CONFIG));
            }
        }
        Ok(())
    }
}

/// The production JMAP calendar transport: real request builders and
/// response parsers for `CalendarEvent/query` + `CalendarEvent/get`
/// (draft-ietf-jmap-calendars-24) and `CalendarEvent/set` booking.
/// Reads expand recurrences server-side and carry the draft's
/// server-computed `utcStart`/`utcEnd` UTC fields; anything off-shape
/// is a typed protocol fault, never a fabricated success.
pub struct JmapCalendarTransport {
    config: JmapCalendarConfig,
}

impl JmapCalendarTransport {
    pub fn new(config: JmapCalendarConfig) -> Result<Self, TransportFault> {
        config.validated()?;
        Ok(Self { config })
    }

    /// Parses one upstream event from its UTC fields (`utcStart`,
    /// `utcEnd` — RFC 3339 with a UTC offset). A missing or malformed
    /// UTC field is a typed protocol fault — never silently repaired.
    fn parse_event(entry: &Value) -> Result<CalendarEventSummary, TransportFault> {
        let id = match entry.get("id") {
            Some(Value::String(id))
                if !id.is_empty() && id.chars().count() <= MAX_EVENT_ID_CHARS =>
            {
                id.clone()
            }
            _ => return Err(TransportFault::Protocol(MSG_BOUND)),
        };
        let title = sanitize_text(entry.get("title"), MAX_TITLE_CHARS)?;
        let description = sanitize_text(entry.get("description"), MAX_EVENT_DESCRIPTION_CHARS)?;
        let start = bounded_timestamp(entry.get("utcStart"))?;
        let end = bounded_timestamp(entry.get("utcEnd"))?;
        OffsetDateTime::parse(&start, &Rfc3339).map_err(|_| TransportFault::Protocol(MSG_SHAPE))?;
        OffsetDateTime::parse(&end, &Rfc3339).map_err(|_| TransportFault::Protocol(MSG_SHAPE))?;
        Ok(CalendarEventSummary {
            id,
            title,
            start,
            end,
            description,
        })
    }

    /// Builds the upstream create-object for one draft. The draft
    /// translates `utcStart`/`utcEnd` into start/duration server-side
    /// (§5.9) and forbids setting them alongside the local fields —
    /// the mutation carries the absolute window only.
    fn event_object(
        &self,
        draft: &CalendarEventDraft,
    ) -> Result<serde_json::Map<String, Value>, TransportFault> {
        let mut event = serde_json::Map::new();
        let mut calendars = serde_json::Map::new();
        calendars.insert(self.config.calendar_id.clone(), Value::Bool(true));
        event.insert("calendarIds".to_owned(), Value::Object(calendars));
        event.insert(
            "title".to_owned(),
            Value::String(draft.title.trim().to_owned()),
        );
        event.insert(
            "utcStart".to_owned(),
            Value::String(utc_z(draft.start.trim())?),
        );
        event.insert("utcEnd".to_owned(), Value::String(utc_z(draft.end.trim())?));
        if let Some(location) = draft.location.as_deref().map(str::trim) {
            let mut locations = serde_json::Map::new();
            let mut named = serde_json::Map::new();
            named.insert("name".to_owned(), Value::String(location.to_owned()));
            locations.insert("loc".to_owned(), Value::Object(named));
            event.insert("locations".to_owned(), Value::Object(locations));
        }
        if let Some(description) = draft.description.as_deref().map(str::trim) {
            event.insert(
                "description".to_owned(),
                Value::String(description.to_owned()),
            );
        }
        Ok(event)
    }

    fn created_id(
        created: &serde_json::Map<String, Value>,
        key: &str,
    ) -> Result<String, TransportFault> {
        match created.get(key).and_then(|event| event.get("id")) {
            Some(Value::String(id))
                if !id.is_empty() && id.chars().count() <= MAX_EVENT_ID_CHARS =>
            {
                Ok(id.clone())
            }
            _ => Err(TransportFault::Protocol(MSG_BOUND)),
        }
    }
}

fn sanitize_text(
    value: Option<&Value>,
    max_chars: usize,
) -> Result<Option<String>, TransportFault> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            if text.chars().count() > max_chars {
                Err(TransportFault::Protocol(MSG_BOUND))
            } else {
                Ok(Some(text.clone()))
            }
        }
        Some(_) => Err(TransportFault::Protocol(MSG_SHAPE)),
    }
}

/// Renders an RFC 3339 instant as a naive local date-time (the shape
/// the JMAP calendar query `after`/`before` filters take); the value
/// is the UTC instant without its offset, paired with `timeZone:
/// Etc/UTC` in the request.
fn local_naive(rfc3339: &str) -> Result<String, TransportFault> {
    const LOCAL: &[time::format_description::FormatItem] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let instant = OffsetDateTime::parse(rfc3339, &Rfc3339)
        .map_err(|_| TransportFault::Protocol(MSG_WINDOW))?;
    instant
        .format(LOCAL)
        .map_err(|_| TransportFault::Protocol(MSG_SHAPE))
}

/// Renders an RFC 3339 instant in canonical UTC (`Z`) form for the
/// `utcStart`/`utcEnd` translated fields.
fn utc_z(rfc3339: &str) -> Result<String, TransportFault> {
    let instant = OffsetDateTime::parse(rfc3339, &Rfc3339)
        .map_err(|_| TransportFault::Protocol(MSG_PROPOSAL_TIME))?;
    instant
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| TransportFault::Protocol(MSG_SHAPE))
}

fn bounded_timestamp(value: Option<&Value>) -> Result<String, TransportFault> {
    match value {
        Some(Value::String(text)) if text.chars().count() <= MAX_TIMESTAMP_CHARS => {
            Ok(text.clone())
        }
        _ => Err(TransportFault::Protocol(MSG_BOUND)),
    }
}

/// Use-time lease enforcement at every credential-bearing transport
/// entry (LIFE-005): the lease must bind this exact capability, the
/// account the exchange names, and still be inside its window, or
/// nothing is exchanged. Where a request carries no caller-named
/// account (booking) the adapter issued the lease for the recorded
/// intent's account moments before, and the exchange re-binds the
/// deployment credential handle.
fn check_lease(
    lease: &ScopedCredentialLease,
    operation: &'static str,
    account: &str,
    now: OffsetDateTime,
) -> Result<(), TransportFault> {
    lease
        .admits(&capability(operation), account, now)
        .map_err(|_| TransportFault::Refused(MSG_LEASE_REFUSED))
}

const MSG_LEASE_REFUSED: &str = "the credential lease does not bind this operation";

fn method_call<'a>(
    response: &'a crate::jmap::JmapResponse,
    call_id: &str,
) -> Result<&'a Value, TransportFault> {
    let found = response
        .find(call_id)
        .ok_or(TransportFault::Protocol(MSG_SHAPE))?;
    if found.name == "error" {
        return Err(crate::jmap::method_fault(&found.arguments));
    }
    Ok(&found.arguments)
}

impl CalendarTransport for JmapCalendarTransport {
    /// The exchange holds the bearer file, so it alone can say whether the
    /// bearer is usable.
    fn readiness(&self, _account: &str) -> Result<(), TransportFault> {
        self.config.exchange.readiness()
    }

    fn read_window(
        &self,
        lease: &ScopedCredentialLease,
        window: &CalendarWindow,
        now: OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, TransportFault> {
        // expandRecurrences requires a flat filter with both after and
        // before (draft-ietf-jmap-calendars-24 §5.11) — exactly what
        // this query sends; expansion is real recurrence expansion, so
        // a recurring series appears once per instance in the window.
        check_lease(lease, CALENDAR_READ_OPERATION, &window.account, now)?;
        let request = JmapRequest {
            using: vec![JMAP_CORE.to_owned(), JMAP_CALENDARS.to_owned()],
            method_calls: vec![
                JmapCall::new(
                    "CalendarEvent/query",
                    serde_json::json!({
                        "accountId": self.config.account_id,
                        "filter": {
                            "after": local_naive(window.start.trim())?,
                            "before": local_naive(window.end.trim())?,
                        },
                        "timeZone": "Etc/UTC",
                        "expandRecurrences": true,
                        "sort": [{ "property": "start", "isAscending": true }],
                        "position": 0,
                        "limit": MAX_EVENTS,
                    }),
                    "q",
                ),
                JmapCall::new(
                    "CalendarEvent/get",
                    serde_json::json!({
                        "accountId": self.config.account_id,
                        "#ids": { "resultOf": "q", "name": "CalendarEvent/query", "path": "/ids" },
                        "properties": ["id", "title", "utcStart", "utcEnd", "description"],
                    }),
                    "g",
                ),
            ],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let list = method_call(&response, "g")?
            .get("list")
            .and_then(Value::as_array)
            .ok_or(TransportFault::Protocol(MSG_SHAPE))?;
        if list.len() > MAX_EVENTS {
            return Err(TransportFault::Protocol(MSG_BOUND));
        }
        list.iter().map(Self::parse_event).collect()
    }

    fn apply(
        &self,
        lease: &ScopedCredentialLease,
        proposal: &CalendarProposal,
        now: OffsetDateTime,
    ) -> Result<CalendarMutationReceipt, BatchFault> {
        check_lease(lease, CALENDAR_PROPOSE_OPERATION, lease.account(), now)?;
        proposal
            .validate()
            .map_err(|_| TransportFault::Protocol(MSG_PROPOSAL_TIME))?;
        // One `CalendarEvent/set` per mutation: creations under stable
        // client ids, updates as JSON Pointer patches (RFC 8620 §5.3).
        let mut create = serde_json::Map::new();
        let mut creation_keys: Vec<String> = Vec::new();
        let mut update = serde_json::Map::new();
        let mut update_ids: Vec<String> = Vec::new();
        match &proposal.mutation {
            CalendarMutation::Create(draft) => {
                creation_keys.push("e".to_owned());
                create.insert("e".to_owned(), Value::Object(self.event_object(draft)?));
            }
            CalendarMutation::BatchCreate { drafts } => {
                for (index, draft) in drafts.iter().enumerate() {
                    let key = format!("d{index}");
                    creation_keys.push(key.clone());
                    create.insert(key, Value::Object(self.event_object(draft)?));
                }
            }
            CalendarMutation::Move {
                event_id,
                start,
                end,
            } => {
                let mut patch = serde_json::Map::new();
                patch.insert("utcStart".to_owned(), Value::String(utc_z(start.trim())?));
                patch.insert("utcEnd".to_owned(), Value::String(utc_z(end.trim())?));
                update.insert(event_id.trim().to_owned(), Value::Object(patch));
                update_ids.push(event_id.trim().to_owned());
            }
            CalendarMutation::Cancel { event_id } => {
                let mut patch = serde_json::Map::new();
                patch.insert("status".to_owned(), Value::String("cancelled".to_owned()));
                update.insert(event_id.trim().to_owned(), Value::Object(patch));
                update_ids.push(event_id.trim().to_owned());
            }
        }
        let mut arguments = serde_json::Map::new();
        arguments.insert(
            "accountId".to_owned(),
            Value::String(self.config.account_id.clone()),
        );
        if !create.is_empty() {
            arguments.insert("create".to_owned(), Value::Object(create));
        }
        if !update.is_empty() {
            arguments.insert("update".to_owned(), Value::Object(update));
        }
        let request = JmapRequest {
            using: vec![JMAP_CORE.to_owned(), JMAP_CALENDARS.to_owned()],
            method_calls: vec![JmapCall::new(
                "CalendarEvent/set",
                Value::Object(arguments),
                "b",
            )],
        };
        let response = self.config.exchange.exchange(&request, lease)?;
        let arguments = method_call(&response, "b")?;
        // RFC 8620 §5.3 permits partial application; preserve applied ids and leave the rest in-doubt.
        let updated = arguments.get("updated").and_then(Value::as_object);
        let created = arguments.get("created").and_then(Value::as_object);
        let mut applied: Vec<String> = update_ids
            .iter()
            .filter(|id| updated.is_some_and(|updated| updated.contains_key(id.as_str())))
            .cloned()
            .collect();
        applied.extend(
            creation_keys
                .iter()
                .filter_map(|key| created.and_then(|created| Self::created_id(created, key).ok())),
        );
        let rejected = ["notCreated", "notUpdated"].iter().any(|field| {
            arguments
                .get(field)
                .and_then(Value::as_object)
                .is_some_and(|not| !not.is_empty())
        });
        if rejected {
            return Err(BatchFault::after(
                applied,
                TransportFault::Protocol(MSG_METHOD_ERROR),
            ));
        }
        if applied.len() != update_ids.len() + creation_keys.len() {
            return Err(BatchFault::after(
                applied,
                TransportFault::Protocol(MSG_SHAPE),
            ));
        }
        Ok(CalendarMutationReceipt { event_ids: applied })
    }
}

/// Implements `calendar.*` capabilities using the shared ledger, transport, and credential issuer.
pub struct CalendarAdapter {
    ledger: Arc<parking_lot::Mutex<odin_ledger::Ledger>>,
    transport: Arc<dyn CalendarTransport>,
    leases: Arc<dyn CredentialLeases>,
    issuer: String,
}

impl CalendarAdapter {
    pub fn new(
        ledger: Arc<parking_lot::Mutex<odin_ledger::Ledger>>,
        transport: Arc<dyn CalendarTransport>,
        leases: Arc<dyn CredentialLeases>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            ledger,
            transport,
            leases,
            issuer: issuer.into(),
        }
    }

    /// Checks local credential and provider readiness without issuing a lease or contacting the provider.
    /// Execution repeats availability checks when issuing its lease.
    pub fn credential_readiness(&self, account: &str) -> Result<(), LifeError> {
        self.leases.availability(account).map_err(lease_into_life)?;
        self.transport
            .readiness(account)
            .map_err(crate::account::readiness_into_life)
    }

    /// `calendar.read` — read-only. No durable effect is recorded.
    pub fn read_window(
        &self,
        window: &CalendarWindow,
        now: OffsetDateTime,
    ) -> Result<Vec<CalendarEventSummary>, LifeError> {
        window.validate()?;
        let lease = self
            .leases
            .issue(&capability(CALENDAR_READ_OPERATION), &window.account, now)
            .map_err(lease_into_life)?;
        let events = self
            .transport
            .read_window(&lease, window, now)
            .map_err(fault_into_life)?;
        if events.len() > MAX_EVENTS {
            return Err(LifeError::Protocol(MSG_BOUND));
        }
        Ok(events)
    }

    /// Records the approved proposal without issuing credentials or contacting the provider.
    /// Reusing an identity requires identical effect details.
    pub(crate) fn record_booking_intent(
        &self,
        identity: &EffectIdentity,
        proposal: &CalendarProposal,
        now: OffsetDateTime,
    ) -> Result<(), LifeError> {
        proposal.validate()?;
        let proposal_id = format!("proposal:{}", identity.idempotency_key);
        crate::account::record_dispatch_intent(
            DurableEffect {
                ledger: &self.ledger,
                issuer: &self.issuer,
                identity,
            },
            &capability(CALENDAR_PROPOSE_OPERATION),
            EffectIntent {
                target_kind: CALENDAR_PROPOSAL_TARGET_KIND,
                target_id: &proposal_id,
                arguments: serde_json::to_value(proposal).map_err(|_| {
                    LifeError::InvalidInput("the proposal could not be canonicalized")
                })?,
            },
            now,
        )
    }

    /// Verifies host approval consumption before applying the proposal; denials reject without effects.
    pub fn settle_booking(
        &self,
        identity: &EffectIdentity,
        proof: &HostConsumeProof,
        now: OffsetDateTime,
    ) -> Result<SettledEffect, LifeError> {
        let transport = Arc::clone(&self.transport);
        let booking_account = self.booking_account(identity)?;
        settle_gated_effect(
            DurableEffect {
                ledger: &self.ledger,
                issuer: &self.issuer,
                identity,
            },
            self.leases.as_ref(),
            EffectRoute {
                capability: &capability(CALENDAR_PROPOSE_OPERATION),
                account: &booking_account,
                result_key: "eventIds",
            },
            proof,
            now,
            move |lease, arguments| -> Result<String, BatchFault> {
                let proposal: CalendarProposal = serde_json::from_value(arguments.clone())
                    .map_err(|_| {
                        TransportFault::Protocol("the recorded booking intent is not a proposal")
                    })?;
                let receipt = transport.apply(lease, &proposal, now)?;
                Ok(receipt.to_result_string()?)
            },
        )
    }

    /// The recorded intent names the account; settlement refuses a
    /// different one. Reading it from the durable arguments keeps the
    /// dispatch-path surface free of caller-choosable scope.
    fn booking_account(&self, identity: &EffectIdentity) -> Result<String, LifeError> {
        let command_id = identity.command_id()?;
        let guard = crate::account::lock_ledger(&self.ledger);
        let command = guard
            .command(&command_id)
            .map_err(|error| LifeError::Ledger {
                class: crate::account::LedgerFailure::Invalid,
                detail: error.to_string(),
            })?
            .ok_or(LifeError::InvalidInput(
                "no recorded intent for this idempotency key",
            ))?;
        command
            .arguments
            .get("account")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(LifeError::InvalidInput(
                "the recorded intent names no account",
            ))
    }

    pub fn ledger(&self) -> &Arc<parking_lot::Mutex<odin_ledger::Ledger>> {
        &self.ledger
    }
}

/// Reads the recorded proposal and applied event ids without contacting the provider or writing state.
pub(crate) fn completed_booking(
    ledger: &parking_lot::Mutex<odin_ledger::Ledger>,
    identity: &EffectIdentity,
) -> Result<(CalendarProposal, CalendarMutationReceipt), LifeError> {
    let command = crate::account::completed_effect(
        ledger,
        identity,
        &capability(CALENDAR_PROPOSE_OPERATION),
    )?;
    let proposal: CalendarProposal = serde_json::from_value(command.arguments.clone())
        .map_err(|_| LifeError::Protocol("the recorded booking intent is not a proposal"))?;
    let receipt = CalendarMutationReceipt::from_settled(&SettledEffect {
        command_id: command.id,
        status: crate::account::EffectStatus::Completed,
        result: command.terminal_result.unwrap_or(Value::Null),
        replayed: true,
    })?;
    Ok((proposal, receipt))
}
