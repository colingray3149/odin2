//! Persist revocations and execution receipts alongside the operation journal.

use super::{now_utc, LEDGER_FILE};
use odin_domain::Digest;
use odin_kernel::token::{RevocationStore, TokenError};
use odin_ledger::operation;
use odin_ledger::{Ledger, LedgerError};
use odin_strict_json::{canonicalize, decode};
use odin_types::CorrelationId;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use time::OffsetDateTime;

use crate::{SidecarError, SidecarErrorCode};

pub(super) const MAX_DETAIL_CHARS: usize = 4096;
pub(super) const RECEIPT_SCHEMA: &str = "OdinEffectReceipt/v1";
const RECEIPT_MAX_BYTES: usize = 1_048_576;

const REVOCATION_KIND: &str = "seat_token_revocation";

#[derive(Clone)]
pub(super) struct StoreRevocations {
    pub(super) ledger: Arc<Mutex<Ledger>>,
}

impl StoreRevocations {
    fn lock(&self) -> Result<MutexGuard<'_, Ledger>, TokenError> {
        self.ledger.lock().map_err(|_| {
            TokenError::Ledger(LedgerError::Publish(
                "revocation store lock was poisoned".to_owned(),
            ))
        })
    }
}

impl RevocationStore for StoreRevocations {
    fn is_revoked(&self, token_id: &odin_domain::SeatTokenId) -> Result<bool, TokenError> {
        let ledger = self.lock()?;
        let mut statement = ledger
            .connection()
            .prepare(
                "SELECT 1 FROM materialized_status
                 WHERE object_kind = ?1 AND object_id = ?2 LIMIT 1",
            )
            .map_err(LedgerError::from)
            .map_err(TokenError::Ledger)?;
        let mut rows = statement
            .query((REVOCATION_KIND, token_id.as_str()))
            .map_err(LedgerError::from)
            .map_err(TokenError::Ledger)?;
        Ok(rows
            .next()
            .map_err(LedgerError::from)
            .map_err(TokenError::Ledger)?
            .is_some())
    }

    fn revoke(
        &mut self,
        token_id: &odin_domain::SeatTokenId,
        revoked_at_ms: u64,
    ) -> Result<(), TokenError> {
        let timestamp = odin_ledger::encode_utc(
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(revoked_at_ms) * 1_000_000)
                .map_err(|_| TokenError::InvalidTimestamp(revoked_at_ms))?,
        )
        .map_err(TokenError::Ledger)?;
        let status = serde_json::json!({
            "token_id": token_id.as_str(),
            "revoked_at_ms": revoked_at_ms,
        });
        let ledger = self.lock()?;
        ledger
            .connection()
            .execute(
                "INSERT INTO materialized_status (
                     object_kind, object_id, revision, status_json,
                     source_event_id, updated_at, stale_after
                 ) VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)
                 ON CONFLICT(object_kind, object_id) DO NOTHING",
                (
                    REVOCATION_KIND,
                    token_id.as_str(),
                    status.to_string(),
                    format!("seat-token-revocation:{}", token_id.as_str()),
                    timestamp,
                ),
            )
            .map_err(LedgerError::from)
            .map_err(TokenError::Ledger)?;
        Ok(())
    }
}

/// Require an observation source so a timestamp cannot be presented without context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEvent {
    pub name: String,
    pub at_ms: u64,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFileChange {
    pub op: String,
    pub path: String,
}

/// Derive admission and settlement from the journal, not the execution receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    pub schema: String,
    pub correlation_id: String,
    pub operation_id: String,
    pub capability: String,
    pub capsule_id: String,
    pub evidence_digest: String,
    pub outcome: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_hex: String,
    pub stdout_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_hex: String,
    pub stderr_bytes: u64,
    pub stderr_truncated: bool,
    pub events: Vec<ReceiptEvent>,
    pub network_connections: Vec<String>,
    pub filesystem_changes: Vec<ReceiptFileChange>,
    pub post_world: Option<String>,
    pub worker_stopped: bool,
    pub residual_workers: u64,
    pub post_world_unchanged: Option<bool>,
}

/// Exclude `evidence_digest` to avoid a self-referential hash.
#[derive(Serialize)]
struct ReceiptEvidence<'a> {
    schema: &'a str,
    correlation_id: &'a str,
    operation_id: &'a str,
    capability: &'a str,
    capsule_id: &'a str,
    outcome: &'a str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout_hex: &'a str,
    stdout_bytes: u64,
    stdout_truncated: bool,
    stderr_hex: &'a str,
    stderr_bytes: u64,
    stderr_truncated: bool,
    events: &'a [ReceiptEvent],
    network_connections: &'a [String],
    filesystem_changes: &'a [ReceiptFileChange],
    post_world: Option<&'a str>,
    worker_stopped: bool,
    residual_workers: u64,
    post_world_unchanged: Option<bool>,
}

impl EffectReceipt {
    fn evidence(&self) -> ReceiptEvidence<'_> {
        ReceiptEvidence {
            schema: &self.schema,
            correlation_id: &self.correlation_id,
            operation_id: &self.operation_id,
            capability: &self.capability,
            capsule_id: &self.capsule_id,
            outcome: &self.outcome,
            exit_code: self.exit_code,
            signal: self.signal,
            stdout_hex: &self.stdout_hex,
            stdout_bytes: self.stdout_bytes,
            stdout_truncated: self.stdout_truncated,
            stderr_hex: &self.stderr_hex,
            stderr_bytes: self.stderr_bytes,
            stderr_truncated: self.stderr_truncated,
            events: &self.events,
            network_connections: &self.network_connections,
            filesystem_changes: &self.filesystem_changes,
            post_world: self.post_world.as_deref(),
            worker_stopped: self.worker_stopped,
            residual_workers: self.residual_workers,
            post_world_unchanged: self.post_world_unchanged,
        }
    }

    pub fn digest(&self) -> Result<Digest, SidecarError> {
        let canonical = canonical_json(&self.evidence(), "effect receipt evidence")?;
        Ok(Digest::hash(&canonical))
    }

    fn canonical_json(&self) -> Result<Vec<u8>, SidecarError> {
        canonical_json(self, "effect receipt")
    }

    pub(super) fn seal_digest(&mut self) -> Result<Digest, SidecarError> {
        let digest = self.digest()?;
        self.evidence_digest = digest.to_string();
        Ok(digest)
    }

    pub(super) fn validate_bounds(&self) -> Result<(), SidecarError> {
        if self.schema != RECEIPT_SCHEMA {
            return Err(receipt_mismatch(format!(
                "receipt schema {:?} is not {RECEIPT_SCHEMA}",
                self.schema
            )));
        }
        validate_capture(
            "stdout",
            &self.stdout_hex,
            self.stdout_bytes,
            self.stdout_truncated,
        )?;
        validate_capture(
            "stderr",
            &self.stderr_hex,
            self.stderr_bytes,
            self.stderr_truncated,
        )?;
        if self.events.len() > 8
            || self.events.iter().any(|event| {
                event.name.is_empty()
                    || event.name.len() > 64
                    || event.detail.is_empty()
                    || event.detail.len() > MAX_DETAIL_CHARS
                    || event.at_ms == 0
            })
        {
            return Err(receipt_mismatch(
                "receipt timeline exceeds its bound or has an empty event",
            ));
        }
        if self.filesystem_changes.len() > 64
            || self.filesystem_changes.iter().any(|change| {
                !matches!(change.op.as_str(), "create" | "write" | "unlink")
                    || change.path.is_empty()
                    || change.path.len() > 4_096
            })
        {
            return Err(receipt_mismatch(
                "receipt filesystem observations exceed their bound",
            ));
        }
        if !self.network_connections.is_empty() {
            return Err(receipt_mismatch(
                "receipt reported network connections without a network observer",
            ));
        }
        Ok(())
    }
}

fn canonical_json(value: &impl Serialize, what: &'static str) -> Result<Vec<u8>, SidecarError> {
    let raw = serde_json::to_vec(value).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::State,
            format!("{what} is not representable: {error}"),
        )
    })?;
    let strict: odin_strict_json::Value = decode(&raw, RECEIPT_MAX_BYTES).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::State,
            format!("{what} is not strict bounded JSON: {error}"),
        )
    })?;
    canonicalize(&strict).map_err(|error| {
        SidecarError::new(
            SidecarErrorCode::State,
            format!("{what} is not canonicalizable: {error}"),
        )
    })
}

fn validate_capture(
    name: &'static str,
    hex: &str,
    captured_bytes: u64,
    truncated: bool,
) -> Result<(), SidecarError> {
    let retained = odin_types::hash::hex_decode(hex)
        .map_err(|error| receipt_mismatch(format!("receipt {name}_hex is malformed: {error}")))?;
    if retained.len() > 65_536
        || captured_bytes > 1_048_576
        || captured_bytes < retained.len() as u64
        || (!truncated && captured_bytes != retained.len() as u64)
    {
        return Err(receipt_mismatch(format!(
            "receipt {name} byte count/truncation contradicts its retained bytes"
        )));
    }
    Ok(())
}

fn receipt_missing(detail: impl Into<String>) -> SidecarError {
    SidecarError::new(SidecarErrorCode::ReceiptMissing, detail)
}

fn receipt_mismatch(detail: impl Into<String>) -> SidecarError {
    SidecarError::new(SidecarErrorCode::ReceiptMismatch, detail)
}

pub(super) struct EffectReceiptStore {
    ledger: Arc<Mutex<Ledger>>,
}

impl EffectReceiptStore {
    pub(super) fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self { ledger }
    }

    pub(super) fn persist(
        &self,
        receipt: &EffectReceipt,
        recorded_at_ms: u64,
    ) -> Result<(), SidecarError> {
        receipt.validate_bounds()?;
        let digest = receipt.digest()?.to_string();
        if digest != receipt.evidence_digest {
            return Err(receipt_mismatch(
                "receipt evidence_digest does not match its canonical observations",
            ));
        }
        let canonical = receipt.canonical_json()?;
        if canonical.len() > RECEIPT_MAX_BYTES {
            return Err(receipt_mismatch(format!(
                "receipt is {} bytes; ceiling is {RECEIPT_MAX_BYTES}",
                canonical.len()
            )));
        }
        let receipt_json = String::from_utf8(canonical).map_err(|error| {
            SidecarError::new(
                SidecarErrorCode::State,
                format!("canonical receipt is not UTF-8: {error}"),
            )
        })?;
        let recorded_at = odin_ledger::encode_utc(now_utc(recorded_at_ms)?)?;
        let ledger = self.ledger.lock().map_err(|_| SidecarError::poisoned())?;
        ledger
            .connection()
            .execute(
                "INSERT INTO effect_receipts (
                     correlation_id, operation_id, receipt_json,
                     receipt_digest, recorded_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    receipt.correlation_id.as_str(),
                    receipt.operation_id.as_str(),
                    receipt_json,
                    digest,
                    recorded_at,
                ),
            )
            .map_err(LedgerError::from)?;
        Ok(())
    }
}

struct StoredReceipt {
    operation_id: String,
    receipt: EffectReceipt,
    digest: String,
}

fn stored_receipt(
    ledger: &Ledger,
    correlation_id: &str,
) -> Result<Option<StoredReceipt>, SidecarError> {
    let mut statement = ledger
        .connection()
        .prepare(
            "SELECT operation_id, length(receipt_json), receipt_json, receipt_digest
             FROM effect_receipts WHERE correlation_id = ?1",
        )
        .map_err(LedgerError::from)?;
    let mut rows = statement
        .query((correlation_id,))
        .map_err(LedgerError::from)?;
    let Some(row) = rows.next().map_err(LedgerError::from)? else {
        return Ok(None);
    };
    let operation_id: String = row.get(0).map_err(LedgerError::from)?;
    let receipt_bytes: i64 = row.get(1).map_err(LedgerError::from)?;
    if receipt_bytes < 0 || receipt_bytes as u64 > RECEIPT_MAX_BYTES as u64 {
        return Err(receipt_mismatch(format!(
            "persisted receipt is {receipt_bytes} bytes; ceiling is {RECEIPT_MAX_BYTES}"
        )));
    }
    let receipt_json: String = row.get(2).map_err(LedgerError::from)?;
    let digest: String = row.get(3).map_err(LedgerError::from)?;
    let strict: odin_strict_json::Value = decode(receipt_json.as_bytes(), RECEIPT_MAX_BYTES)
        .map_err(|error| {
            receipt_mismatch(format!("persisted receipt is not strict JSON: {error}"))
        })?;
    let canonical = canonicalize(&strict).map_err(|error| {
        receipt_mismatch(format!("persisted receipt is not canonicalizable: {error}"))
    })?;
    if canonical.as_slice() != receipt_json.as_bytes() {
        return Err(receipt_mismatch(
            "persisted receipt bytes are not canonical JSON",
        ));
    }
    let receipt = serde_json::from_slice(&canonical).map_err(|error| {
        receipt_mismatch(format!("persisted receipt schema is invalid: {error}"))
    })?;
    Ok(Some(StoredReceipt {
        operation_id,
        receipt,
        digest,
    }))
}

pub(super) fn verified_effect_receipt(
    ledger: &Ledger,
    correlation_id: &CorrelationId,
) -> Result<EffectReceipt, SidecarError> {
    let operation = operation::operation_row(ledger.connection(), correlation_id.as_str())?
        .ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::UnknownOperation,
                format!(
                    "correlation {} has no durable operation",
                    correlation_id.as_str()
                ),
            )
        })?;
    let stored = stored_receipt(ledger, correlation_id.as_str())?.ok_or_else(|| {
        receipt_missing(format!(
            "operation {} has no persisted effect receipt",
            operation.operation_id
        ))
    })?;
    let receipt = stored.receipt;
    if receipt.correlation_id != correlation_id.as_str()
        || receipt.operation_id != operation.operation_id
        || stored.operation_id != operation.operation_id
    {
        return Err(receipt_mismatch(
            "receipt correlation or operation does not match the durable operation",
        ));
    }
    receipt.validate_bounds()?;
    let digest = receipt.digest()?.to_string();
    if receipt.evidence_digest != digest || stored.digest != digest {
        return Err(receipt_mismatch(
            "receipt digest does not match its canonical observations or stored index",
        ));
    }
    match operation.evidence_digest.as_deref() {
        Some(bound) if bound == digest => Ok(receipt),
        Some(bound) => Err(receipt_mismatch(format!(
            "receipt digest {digest} does not match durable operation evidence {bound}"
        ))),
        None => Err(receipt_missing(format!(
            "operation {} has no durable evidence binding",
            operation.operation_id
        ))),
    }
}

/// Use a separate read-only WAL connection and verify the receipt against the operation journal.
pub fn effect_receipt_at(
    state_root: &Path,
    correlation_id: &CorrelationId,
) -> Result<EffectReceipt, SidecarError> {
    let ledger_path = state_root.join(LEDGER_FILE);
    let ledger = Ledger::open(&ledger_path).map_err(SidecarError::from)?;
    verified_effect_receipt(&ledger, correlation_id)
}
