//! Persist receipts before returning their digests so journal evidence resolves to durable bytes.

use std::sync::{Arc, Mutex, MutexGuard};

use odin_ledger::{encode_utc, Ledger, LedgerError};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ids::Digest;
use crate::operation::AdapterOperationRecord;
use crate::AdapterError;

/// Implementations must validate and persist the record and evidence before returning their digest.
pub trait EffectReceiptSink: Send + Sync {
    fn persist_receipt(
        &self,
        correlation_id: &str,
        receipt: &AdapterOperationRecord,
        evidence: Option<&Value>,
    ) -> Result<Digest, AdapterError>;
}

pub struct LedgerEffectReceiptSink {
    ledger: Arc<Mutex<Ledger>>,
    clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}

impl LedgerEffectReceiptSink {
    /// Use the sink's clock rather than caller-supplied timestamps for persistence.
    pub fn new(
        ledger: Arc<Mutex<Ledger>>,
        clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    ) -> Self {
        Self { ledger, clock }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Ledger>, AdapterError> {
        self.ledger.lock().map_err(|_| AdapterError::Receipt {
            detail: "shared ledger lock is poisoned".to_owned(),
        })
    }
}

impl EffectReceiptSink for LedgerEffectReceiptSink {
    fn persist_receipt(
        &self,
        correlation_id: &str,
        receipt: &AdapterOperationRecord,
        evidence: Option<&Value>,
    ) -> Result<Digest, AdapterError> {
        receipt.validate()?;
        // Hash the stored envelope so the journal digest covers both the record and evidence.
        let envelope = serde_json::json!({
            "evidence": evidence,
            "operation": receipt.to_wire(),
        });
        let canonical =
            odin_strict_json::canonicalize(&envelope).map_err(|error| AdapterError::Canonical {
                detail: error.to_string(),
            })?;
        let receipt_json =
            String::from_utf8(canonical).map_err(|error| AdapterError::Canonical {
                detail: format!("receipt canonical bytes are not UTF-8: {error}"),
            })?;
        let digest = crate::ids::Digest::hash(receipt_json.as_bytes());
        let receipt_digest = digest.to_string();
        let recorded_at = encode_utc((self.clock)()).map_err(|error| AdapterError::Receipt {
            detail: format!("receipt timestamp failed: {error}"),
        })?;
        let operation_id = receipt.operation_id.as_str().to_owned();
        let mut ledger = self.lock()?;
        ledger
            .with_tx(|tx| {
                // Replays may reuse identical receipts, but a correlation cannot change its digest.
                let inserted = tx.execute(
                    "INSERT INTO effect_receipts (
                         correlation_id, operation_id, receipt_json,
                         receipt_digest, recorded_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(correlation_id) DO NOTHING",
                    [
                        correlation_id,
                        operation_id.as_str(),
                        receipt_json.as_str(),
                        receipt_digest.as_str(),
                        recorded_at.as_str(),
                    ],
                )?;
                if inserted == 0 {
                    let recorded: String = tx.query_row(
                        "SELECT receipt_digest FROM effect_receipts
                         WHERE correlation_id = ?1",
                        [correlation_id],
                        |row| row.get(0),
                    )?;
                    if recorded != receipt_digest {
                        return Err(LedgerError::Conflict(format!(
                            "effect receipt for correlation {correlation_id} already records \
                             digest {recorded}; refusing to overwrite with {receipt_digest}"
                        )));
                    }
                }
                Ok(())
            })
            .map_err(|error| AdapterError::Receipt {
                detail: error.to_string(),
            })?;
        Ok(digest)
    }
}
