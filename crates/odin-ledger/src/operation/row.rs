//! Row and codec contracts for the durable operation journal: canonical
//! effect-state names, durable row values, journal row/outcome shapes, and
//! the exact column decoder every read shares.

use odin_domain::operation::EffectState;
use time::OffsetDateTime;

use crate::{LedgerError, LedgerResult};

pub(super) const STATE_PREPARED: &str = "prepared";
pub(super) const STATE_EFFECT_STARTED: &str = "effect_started";
pub(super) const STATE_IN_DOUBT: &str = "in_doubt";

pub const LEGACY_CAPSULE_ID: &str = "legacy-authority";
pub const RECONCILIATION_UNRESOLVABLE: &str = "{\"expected_post_world\":null,\"pre_world\":null}";

pub(super) fn parse_state(raw: &str) -> LedgerResult<EffectState> {
    EffectState::parse(raw).map_err(|error| {
        LedgerError::invalid_data_caused_by("invalid operation effect state", error)
    })
}

pub(super) fn state_text(state: EffectState) -> &'static str {
    state.as_str()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRow {
    pub correlation_id: String,
    pub operation_id: String,
    pub capsule_id: String,
    pub seat_id: String,
    pub token_id: String,
    pub session_id: String,
    pub policy_digest: String,
    pub listing_digest: String,
    pub capability: String,
    pub request_digest: String,
    pub request_json: String,
    pub effect_state: EffectState,
    pub reconciliation_json: String,
    pub evidence_digest: Option<String>,
    pub executor_id: String,
    pub prepared_binding: String,
    pub binding_digest: String,
    pub updated_at: String,
}

/// A fresh operation to journal. Identifier strings must already be validated
/// by the authority; the store re-checks only shape-independent invariants.
#[derive(Clone, Debug)]
pub struct NewOperation<'a> {
    pub capsule_id: &'a str,
    pub seat_id: &'a str,
    pub token_id: &'a str,
    pub session_id: &'a str,
    pub policy_digest: &'a str,
    pub listing_digest: &'a str,
    pub executor_id: &'a str,
    pub prepared_binding: &'a str,
    pub binding_digest: &'a str,
    pub correlation_id: &'a str,
    pub capability: &'a str,
    pub request_digest: &'a str,
    pub request_json: &'a str,
    pub reconciliation_json: &'a str,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareOutcome {
    Prepared { operation_id: String },
    Replay { row: Box<OperationRow> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionOutcome {
    Applied,
    Replay,
}

pub(super) const OPERATION_COLUMNS: &str = "correlation_id, operation_id, capsule_id, seat_id, \
     token_id, session_id, policy_digest, listing_digest, capability, request_digest, \
     request_json, effect_state, reconciliation_json, evidence_digest, executor_id, \
     prepared_binding, binding_digest, updated_at";

pub(super) fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRow> {
    let effect_state: String = row.get(11)?;
    let effect_state = parse_state(&effect_state).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(OperationRow {
        correlation_id: row.get(0)?,
        operation_id: row.get(1)?,
        capsule_id: row.get(2)?,
        seat_id: row.get(3)?,
        token_id: row.get(4)?,
        session_id: row.get(5)?,
        policy_digest: row.get(6)?,
        listing_digest: row.get(7)?,
        capability: row.get(8)?,
        request_digest: row.get(9)?,
        request_json: row.get(10)?,
        effect_state,
        reconciliation_json: row.get(12)?,
        evidence_digest: row.get(13)?,
        executor_id: row.get(14)?,
        prepared_binding: row.get(15)?,
        binding_digest: row.get(16)?,
        updated_at: row.get(17)?,
    })
}
