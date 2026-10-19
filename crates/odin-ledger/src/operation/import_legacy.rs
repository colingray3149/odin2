//! Imports legacy sidecar state once, preserving `in_doubt` and mapping
//! interrupted `effect_started` operations to `in_doubt`.

use std::collections::BTreeMap;

use odin_domain::operation::EffectState;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Deserialize;
use time::OffsetDateTime;

use super::row::{parse_state, state_text, LEGACY_CAPSULE_ID, RECONCILIATION_UNRESOLVABLE};
use crate::{encode_utc, LedgerError, LedgerResult};

pub fn import_receipt_present(conn: &Connection) -> LedgerResult<bool> {
    let present: Option<i64> = conn
        .query_row("SELECT id FROM authority_import WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(present.is_some())
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyGrant {
    capabilities: Vec<String>,
    stop_budget: u64,
    spend_budget: u64,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyLimits {
    requests: u64,
    stops: u64,
    spend: u64,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyUsage {
    requests: u64,
    stops: u64,
    spend: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAuthorityState {
    schema: String,
    grant: LegacyGrant,
    limits: LegacyLimits,
    usage: LegacyUsage,
    policy: LegacyPolicyState,
    operations: BTreeMap<String, LegacyOperationBinding>,
    stops: BTreeMap<String, LegacyStopRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPolicyState {
    operations: BTreeMap<String, LegacyPolicyRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPolicyRecord {
    request: LegacyRequest,
    state: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyCost {
    requests: u64,
    stops: u64,
    spend: u64,
}

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRequest {
    correlation_id: String,
    operation_id: String,
    capability: String,
    requested_grant: LegacyGrant,
    cost: LegacyCost,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyOperationBinding {
    operation_id: String,
    session_id: String,
    permit_issued: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStopRecord {
    helper: Option<serde_json::Value>,
    state: String,
    survivors: Vec<serde_json::Value>,
}

/// Counts recorded in the one-time import receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LegacyImportCounts {
    pub operations: usize,
    pub stops: usize,
    pub remapped_effect_started: usize,
    pub zero_file: bool,
}

/// Imports once and records a receipt even for empty state;
/// unfinished effects remain blocking as `in_doubt`.
#[doc(hidden)]
pub fn import_legacy_authority(
    tx: &Transaction<'_>,
    state_bytes: &[u8],
    now: OffsetDateTime,
) -> LedgerResult<LegacyImportCounts> {
    if import_receipt_present(tx)? {
        return Err(LedgerError::Conflict(
            "legacy authority state was already imported".to_owned(),
        ));
    }
    // The archive digest is computed over the EXACT source bytes; a caller
    // supplied digest is never trusted verbatim.
    let source_digest = blake3::hash(state_bytes).to_hex().to_string();
    let source_len = state_bytes.len() as i64;
    let trimmed = trim_utf8(state_bytes);
    let (state, zero_file) = if trimmed.is_empty() {
        return record_receipt(
            tx,
            &ReceiptInput {
                source_schema: String::new(),
                source_digest: Some(source_digest),
                source_len,
                archived_grant: serde_json::Value::Null,
                archived_limits: serde_json::Value::Null,
                archived_usage: serde_json::Value::Null,
                counts: LegacyImportCounts {
                    operations: 0,
                    stops: 0,
                    remapped_effect_started: 0,
                    zero_file: true,
                },
                now,
            },
        );
    } else {
        let parsed: LegacyAuthorityState = serde_json::from_slice(trimmed).map_err(|error| {
            LedgerError::InvalidSnapshot(format!("legacy authority state rejected: {error}"))
        })?;
        (parsed, false)
    };
    if state.schema != "OdinSidecarState/v2" {
        return Err(LedgerError::InvalidSnapshot(format!(
            "legacy authority schema {:?} is not OdinSidecarState/v2",
            state.schema
        )));
    }

    // Per-row cost checks run per record below; the aggregate of validated
    // costs is compared against the archived cumulative usage at the end of
    // the import (sum of row costs must never exceed recorded consumption),
    // while usage == limits is a VALID exhausted state that imports and lets
    // the next operation deny.
    if state.grant.stop_budget > state.limits.stops
        || state.grant.spend_budget > state.limits.spend
        || state.usage.requests > state.limits.requests
        || state.usage.stops > state.limits.stops
        || state.usage.spend > state.limits.spend
    {
        return Err(LedgerError::InvalidSnapshot(
            "legacy grant/usage exceed the archived limits".to_owned(),
        ));
    }
    // Every durable operation binding must appear exactly once in the
    // policy map and vice versa: extra or missing keys block the import.
    if state.operations.len() != state.policy.operations.len()
        || state
            .operations
            .keys()
            .any(|key| !state.policy.operations.contains_key(key))
    {
        return Err(LedgerError::InvalidSnapshot(
            "legacy operations and policy key sets diverge".to_owned(),
        ));
    }
    // Legacy cumulative usage is imported atomically into the durable
    // counters under the legacy authority session so prior consumption keeps
    // binding future ceilings.
    let legacy_session = LEGACY_CAPSULE_ID;
    let updated_at = encode_utc(now)?;
    tx.execute(
        "INSERT INTO operation_usage (session_id, requests, stops, spend, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(session_id) DO UPDATE SET \
         requests = requests + ?2, stops = stops + ?3, spend = spend + ?4, updated_at = ?5",
        params![
            legacy_session,
            state.usage.requests as i64,
            state.usage.stops as i64,
            state.usage.spend as i64,
            updated_at,
        ],
    )?;
    let mut cost_totals = (u128::default(), u128::default(), u128::default());
    let mut counts = LegacyImportCounts {
        operations: 0,
        stops: 0,
        remapped_effect_started: 0,
        zero_file,
    };

    for (correlation_id, record) in &state.policy.operations {
        let binding = state.operations.get(correlation_id).ok_or_else(|| {
            LedgerError::InvalidSnapshot(format!(
                "legacy policy record {correlation_id} has no durable operation binding"
            ))
        })?;
        let legacy_state = parse_state(&record.state).map_err(|_| {
            LedgerError::InvalidSnapshot(format!(
                "legacy operation {correlation_id} carries unknown state {:?}",
                record.state
            ))
        })?;
        let (effect_state, remapped) = match legacy_state {
            EffectState::EffectStarted => (EffectState::InDoubt, true),
            other => (other, false),
        };
        if remapped {
            counts.remapped_effect_started += 1;
        }
        // The request grant must live inside the archived state grant; a
        // request claiming more authority than the state grant carried is a
        // contradiction that rejects the whole import.
        if record.request.requested_grant.stop_budget > state.grant.stop_budget
            || record.request.requested_grant.spend_budget > state.grant.spend_budget
            || record
                .request
                .requested_grant
                .capabilities
                .iter()
                .any(|class| !state.grant.capabilities.contains(class))
        {
            return Err(LedgerError::InvalidSnapshot(format!(
                "legacy request {correlation_id} widens the archived state grant"
            )));
        }
        // Per-operation cost must be bounded by the archived limits and
        // already accounted inside the archived cumulative usage.
        if record.request.cost.requests > state.limits.requests
            || record.request.cost.stops > state.limits.stops
            || record.request.cost.spend > state.limits.spend
        {
            return Err(LedgerError::InvalidSnapshot(format!(
                "legacy request {correlation_id} cost exceeds the archived limits"
            )));
        }
        // Accumulate; the aggregate comparison happens after the loop so a
        // set of individually-valid rows cannot jointly exceed the usage.
        cost_totals.0 += u128::from(record.request.cost.requests);
        cost_totals.1 += u128::from(record.request.cost.stops);
        cost_totals.2 += u128::from(record.request.cost.spend);
        // permit_issued decides whether an effect could have started: a
        // permit with a prepared-only row, or a missing permit with a
        // started/uncertain row, is a binding contradiction.
        match (binding.permit_issued, legacy_state) {
            (true, EffectState::Prepared) | (false, EffectState::EffectStarted) => {
                return Err(LedgerError::InvalidSnapshot(format!(
                    "legacy binding {correlation_id} permit_issued={} contradicts state {}",
                    binding.permit_issued, record.state
                )));
            }
            (false, EffectState::InDoubt) => {
                return Err(LedgerError::InvalidSnapshot(format!(
                    "legacy binding {correlation_id} has in_doubt state without an issued permit"
                )));
            }
            _ => {}
        }
        let operation_id = binding.operation_id.trim();
        if operation_id != record.request.operation_id {
            return Err(LedgerError::InvalidSnapshot(format!(
                "legacy binding {correlation_id} names operation {operation_id} but its \
                 request names {}",
                record.request.operation_id
            )));
        }
        if correlation_id.as_str() != record.request.correlation_id {
            return Err(LedgerError::InvalidSnapshot(format!(
                "legacy key {correlation_id} does not match the embedded request \
                 correlation {}",
                record.request.correlation_id
            )));
        }
        let request_json = serde_json::to_string(&record.request)
            .map_err(|error| LedgerError::InvalidSnapshot(error.to_string()))?;
        let request_digest = blake3::hash(request_json.as_bytes()).to_hex().to_string();
        tx.execute(
            "INSERT INTO operation_journal (correlation_id, operation_id, capsule_id, \
             seat_id, token_id, session_id, policy_digest, listing_digest, capability, \
             request_digest, request_json, effect_state, reconciliation_json, \
             evidence_digest, executor_id, prepared_binding, binding_digest, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, ?14, ?15, ?16, ?17)",
            params![
                correlation_id,
                operation_id,
                LEGACY_CAPSULE_ID,
                LEGACY_CAPSULE_ID,
                "legacy-token",
                binding.session_id,
                "legacy-policy",
                "legacy-listing",
                record.request.capability,
                request_digest,
                request_json,
                state_text(effect_state),
                RECONCILIATION_UNRESOLVABLE,
                "legacy",
                RECONCILIATION_UNRESOLVABLE,
                RECONCILIATION_UNRESOLVABLE,
                updated_at,
            ],
        )?;
        counts.operations += 1;
    }

    for (correlation_id, record) in &state.stops {
        if record.state != "requested" && record.state != "stopped" && record.state != "failed" {
            return Err(LedgerError::InvalidSnapshot(format!(
                "legacy stop {correlation_id} carries unknown state {:?}",
                record.state
            )));
        }
        let terminal = record.state != "requested";
        let mut evidence = serde_json::Map::new();
        if let Some(helper) = &record.helper {
            evidence.insert("helper".to_owned(), helper.clone());
        }
        if !record.survivors.is_empty() {
            evidence.insert(
                "survivors".to_owned(),
                serde_json::Value::Array(record.survivors.clone()),
            );
        }
        let evidence_json = serde_json::to_string(&serde_json::Value::Object(evidence))
            .map_err(|error| LedgerError::InvalidSnapshot(error.to_string()))?;
        tx.execute(
            "INSERT INTO stop_intent (correlation_id, operation_id, seat_id, token_id, \
             session_id, policy_digest, listing_digest, capsule_id, state, evidence_json, \
             requested_at, settled_at) \
             VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                correlation_id,
                LEGACY_CAPSULE_ID,
                "legacy-token",
                LEGACY_CAPSULE_ID,
                "legacy-policy",
                "legacy-listing",
                LEGACY_CAPSULE_ID,
                record.state,
                evidence_json,
                updated_at,
                if terminal { Some(&updated_at) } else { None },
            ],
        )?;
        counts.stops += 1;
    }

    if cost_totals.0 > u128::from(state.usage.requests)
        || cost_totals.1 > u128::from(state.usage.stops)
        || cost_totals.2 > u128::from(state.usage.spend)
    {
        return Err(LedgerError::InvalidSnapshot(
            "summed legacy request costs exceed the archived cumulative usage".to_owned(),
        ));
    }
    record_receipt(
        tx,
        &ReceiptInput {
            source_schema: state.schema,
            source_digest: Some(source_digest),
            source_len,
            archived_grant: serde_json::to_value(&state.grant).unwrap_or(serde_json::Value::Null),
            archived_limits: serde_json::to_value(&state.limits).unwrap_or(serde_json::Value::Null),
            archived_usage: serde_json::to_value(&state.usage).unwrap_or(serde_json::Value::Null),
            counts,
            now,
        },
    )?;
    Ok(counts)
}

struct ReceiptInput {
    source_schema: String,
    source_digest: Option<String>,
    source_len: i64,
    archived_grant: serde_json::Value,
    archived_limits: serde_json::Value,
    archived_usage: serde_json::Value,
    counts: LegacyImportCounts,
    now: OffsetDateTime,
}

fn record_receipt(tx: &Transaction<'_>, input: &ReceiptInput) -> LedgerResult<LegacyImportCounts> {
    let receipt = serde_json::json!({
        "schema": "OdinAuthorityImportReceipt/v1",
        "source_schema": input.source_schema,
        "source_digest": input.source_digest,
        "source_bytes": input.source_len,
        "archived_grant": input.archived_grant,
        "archived_limits": input.archived_limits,
        "archived_usage": input.archived_usage,
        "imported_operations": input.counts.operations,
        "imported_stops": input.counts.stops,
        "remapped_effect_started": input.counts.remapped_effect_started,
        "zero_file": input.counts.zero_file,
    });
    tx.execute(
        "INSERT INTO authority_import (id, source_schema, source_sha256, receipt_json, \
         imported_operations, imported_stops, remapped_effect_started, zero_file, imported_at) \
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            input.source_schema,
            input.source_digest,
            receipt.to_string(),
            input.counts.operations as i64,
            input.counts.stops as i64,
            input.counts.remapped_effect_started as i64,
            i64::from(input.counts.zero_file),
            encode_utc(input.now)?,
        ],
    )?;
    Ok(input.counts)
}

fn trim_utf8(bytes: &[u8]) -> &[u8] {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return bytes,
    };
    text.trim().as_bytes()
}

#[cfg(test)]
mod legacy_import_strictness {
    use super::*;
    use crate::migration;
    use crate::operation::{prepare_operation, NewOperation, PrepareOutcome};

    fn import(state: &str) -> LedgerResult<LegacyImportCounts> {
        let mut connection = Connection::open_in_memory().unwrap();
        migration::migrate(&mut connection).unwrap();
        let tx = connection.transaction().unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        let outcome = import_legacy_authority(&tx, state.as_bytes(), now);
        tx.commit().unwrap();
        outcome
    }

    const BASE: &str = r#"{
        "schema": "OdinSidecarState/v2",
        "grant": {"capabilities": ["read","write"], "stop_budget": 5, "spend_budget": 100},
        "limits": {"requests": 10, "stops": 5, "spend": 200},
        "usage": {"requests": 3, "stops": 1, "spend": 40},
        "policy": {"operations": {
            "aabbccddeeff00112233445566778899": {
                "request": {
                    "correlation_id": "aabbccddeeff00112233445566778899",
                    "operation_id": "op-legacy",
                    "capability": "write",
                    "requested_grant": {"capabilities": ["write"], "stop_budget": 2, "spend_budget": 30},
                    "cost": {"requests": 1, "stops": 0, "spend": 10}
                },
                "state": "committed"
            }
        }},
        "operations": {
            "aabbccddeeff00112233445566778899": {
                "operation_id": "op-legacy",
                "session_id": "session-legacy",
                "permit_issued": false
            }
        },
        "stops": {}
    }"#;

    #[test]
    fn valid_state_imports_usage_and_operations() {
        let counts = import(BASE).expect("valid legacy state imports");
        assert_eq!(counts.operations, 1);
        assert!(!counts.zero_file);
    }

    #[test]
    fn exhausted_usage_at_limits_imports_and_blocks_nothing_here() {
        let exhausted = BASE
            .replace("\"requests\": 3,", "\"requests\": 10,")
            .replace("\"stops\": 1,", "\"stops\": 5,")
            .replace("\"spend\": 40,", "\"spend\": 200,");
        let counts = import(&exhausted).expect("usage == limits is a valid exhausted state");
        assert_eq!(counts.operations, 1);
    }

    #[test]
    fn aggregate_costs_over_usage_reject() {
        let second_row = r#","bbccddeeff0011223344556677889900": {
                "request": {
                    "correlation_id": "bbccddeeff0011223344556677889900",
                    "operation_id": "op-legacy-2",
                    "capability": "write",
                    "requested_grant": {"capabilities": ["write"], "stop_budget": 2, "spend_budget": 30},
                    "cost": {"requests": 3, "stops": 0, "spend": 10}
                },
                "state": "committed"
            }"#;
        let tampered = BASE.replace(
            "                \"state\": \"committed\"\n            }\n        }},",
            "                \"state\": \"committed\"\n            },\n            \"bbccddeeff0011223344556677889900\": {\n                \"request\": {\n                    \"correlation_id\": \"bbccddeeff0011223344556677889900\",\n                    \"operation_id\": \"op-legacy-2\",\n                    \"capability\": \"write\",\n                    \"requested_grant\": {\"capabilities\": [\"write\"], \"stop_budget\": 2, \"spend_budget\": 30},\n                    \"cost\": {\"requests\": 3, \"stops\": 0, \"spend\": 10}\n                },\n                \"state\": \"committed\"\n            }\n        }},",
        );
        let tampered = tampered.replace(
            "\"aabbccddeeff00112233445566778899\": {\n                \"operation_id\": \"op-legacy\",",
            "\"aabbccddeeff00112233445566778899\": {\n                \"operation_id\": \"op-legacy\",\n                \"session_id\": \"session-legacy\",\n                \"permit_issued\": false\n            },\n            \"bbccddeeff0011223344556677889900\": {\n                \"operation_id\": \"op-legacy-2\",\n                \"session_id\": \"session-legacy\",\n                \"permit_issued\": false",
        );
        // Individually valid (1+3 <= 3? no: aggregate 4 > usage 3) → reject.
        let _ = second_row;
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn zero_file_source_records_a_receipt() {
        let counts = import("   ").expect("zero-file imports with receipt");
        assert!(counts.zero_file);
        assert_eq!(counts.operations, 0);
    }

    #[test]
    fn key_mismatch_rejects() {
        let tampered = BASE.replace(
            "\"correlation_id\": \"aabbccddeeff00112233445566778899\"",
            "\"correlation_id\": \"11111111111111111111111111111111\"",
        );
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn widened_request_grant_rejects() {
        let tampered = BASE.replace("\"stop_budget\": 2,", "\"stop_budget\": 9,");
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn cost_beyond_limits_rejects() {
        let tampered = BASE.replace("\"spend\": 10", "\"spend\": 500");
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn usage_beyond_limits_rejects() {
        let tampered = BASE.replace("\"requests\": 3,", "\"requests\": 99,");
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn grant_beyond_limits_rejects() {
        let tampered = BASE.replace("\"spend_budget\": 100", "\"spend_budget\": 900");
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn permit_contradictions_reject() {
        let issued = BASE.replace("\"permit_issued\": false", "\"permit_issued\": true");
        assert!(
            import(&issued).is_ok(),
            "legacy terminal rows retain the issued-permit history"
        );
        let tampered = issued.replace("\"state\": \"committed\"", "\"state\": \"prepared\"");
        assert!(import(&tampered).is_err());
        let tampered = BASE.replace("\"state\": \"committed\"", "\"state\": \"in_doubt\"");
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn unknown_fields_reject() {
        let tampered = BASE.replace(
            "\"schema\": \"OdinSidecarState/v2\"",
            "\"schema\": \"OdinSidecarState/v2\", \"extra\": 1",
        );
        assert!(import(&tampered).is_err());
    }

    #[test]
    fn duplicate_prepare_same_request_replays_and_conflicting_request_errors() {
        let mut connection = Connection::open_in_memory().unwrap();
        migration::migrate(&mut connection).unwrap();
        let new = |digest: &'static str| NewOperation {
            capsule_id: "capsule-a",
            seat_id: "seat.one",
            token_id: "token.one",
            session_id: "session.one",
            policy_digest: "policy.one",
            listing_digest: "listing.one",
            executor_id: "odin.omp.host_tools",
            prepared_binding: "{\"binding\":true}",
            binding_digest: "binding-digest",
            correlation_id: "00112233445566778899aabbccddeeff",
            capability: "tool.write",
            request_digest: digest,
            request_json: "{}",
            reconciliation_json: "{}",
            now: OffsetDateTime::from_unix_timestamp(1_000).unwrap(),
        };
        let tx = connection.transaction().unwrap();
        assert!(matches!(
            prepare_operation(&tx, &new("digest-a")).unwrap(),
            PrepareOutcome::Prepared { .. }
        ));
        assert!(matches!(
            prepare_operation(&tx, &new("digest-a")).unwrap(),
            PrepareOutcome::Replay { .. }
        ));
        assert!(prepare_operation(&tx, &new("digest-b")).is_err());
        tx.commit().unwrap();
    }
}
