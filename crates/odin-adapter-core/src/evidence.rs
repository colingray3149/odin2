//! Persist receipts before returning their digests so journal evidence resolves to durable bytes.

use std::sync::{Arc, Mutex, MutexGuard};

use odin_ledger::{encode_utc, Ledger, LedgerError};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ids::Digest;
use crate::operation::AdapterOperationRecord;
use crate::AdapterError;

/// Read and validate the journal's final adapter recovery evidence, preserving the original receipt.
pub fn read_recovered_receipt(
    ledger: &Ledger,
    row: &odin_ledger::operation::OperationRow,
) -> Result<Value, AdapterError> {
    use rusqlite::OptionalExtension;
    let fail = |detail: String| AdapterError::Receipt { detail };
    let expected = row
        .recovery_evidence_digest
        .as_deref()
        .ok_or_else(|| fail("operation has no recovery evidence".to_owned()))?;
    let query = |table: &str| -> Result<Option<(String, String)>, AdapterError> {
        let sql = format!("SELECT receipt_json, receipt_digest FROM {table} WHERE correlation_id = ?1 AND operation_id = ?2 AND receipt_digest = ?3");
        ledger
            .connection()
            .query_row(
                &sql,
                [
                    row.correlation_id.as_str(),
                    row.operation_id.as_str(),
                    expected,
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|error| fail(error.to_string()))
    };
    let (json, digest) = match query("recovery_effect_receipts")? {
        Some(receipt) => receipt,
        None => query("effect_receipts")?
            .ok_or_else(|| fail("recovery receipt not found".to_owned()))?,
    };
    let value: Value = serde_json::from_str(&json).map_err(|error| fail(error.to_string()))?;
    let canonical =
        odin_strict_json::canonicalize(&value).map_err(|error| fail(error.to_string()))?;
    let record = AdapterOperationRecord::from_wire(&value["operation"])?;
    let binding = odin_kernel::RecordedBinding::parse(row)
        .ok_or_else(|| fail("invalid recorded binding".to_owned()))?;
    let request: Value =
        serde_json::from_str(&row.request_json).map_err(|error| fail(error.to_string()))?;
    let input = request
        .get("arguments")
        .ok_or_else(|| fail("missing journal arguments".to_owned()))?;
    let payload = odin_kernel::Payload::from_arguments(input);
    if canonical != json.as_bytes()
        || Digest::hash(json.as_bytes()).to_string() != digest
        || digest != expected
        || record.operation_id.as_str() != row.operation_id
        || record.kind.as_str() != row.capability
        || record.input_digest != payload.digest
        || record.input_schema.as_str() != binding.contract.input_schema_ref
        || record.output_schema.as_str() != binding.contract.output_schema_ref
        || record.state != crate::operation::OperationRecordState::Succeeded
        || record.output_digest.is_none()
        || value.pointer("/evidence/kind").and_then(Value::as_str) != Some(record.kind.as_str())
        || value.pointer("/evidence/adapter_identity")
            != Some(
                &serde_json::to_value(&record.adapter).map_err(|error| fail(error.to_string()))?,
            )
        || request.get("arguments_digest").and_then(Value::as_str)
            != Some(payload.digest.to_string().as_str())
        || value
            .pointer("/evidence/response_digest")
            .and_then(Value::as_str)
            != record
                .output_digest
                .map(|digest| digest.to_string())
                .as_deref()
    {
        return Err(fail(
            "recovery receipt does not match its journal".to_owned(),
        ));
    }
    Ok(value)
}

/// Implementations must validate and persist the record and evidence before returning their digest.
pub trait EffectReceiptSink: Send + Sync {
    fn persist_receipt(
        &self,
        correlation_id: &str,
        receipt: &AdapterOperationRecord,
        evidence: Option<&Value>,
    ) -> Result<Digest, AdapterError>;
    /// Reuse an original successful receipt for this exact bound operation.
    fn existing_receipt(
        &self,
        _correlation_id: &str,
        _receipt: &AdapterOperationRecord,
    ) -> Result<Option<Digest>, AdapterError> {
        Ok(None)
    }
    /// Persist a distinct recovery witness without replacing the original effect receipt.
    fn persist_recovery_receipt(
        &self,
        _correlation_id: &str,
        _receipt: &AdapterOperationRecord,
        _evidence: &Value,
    ) -> Result<Digest, AdapterError> {
        Err(AdapterError::Receipt {
            detail: "recovery receipt storage unavailable".to_owned(),
        })
    }
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
        self.ledger.lock().map_err(|error| AdapterError::Receipt {
            detail: format!("shared ledger lock is poisoned: {error}"),
        })
    }
}

impl EffectReceiptSink for LedgerEffectReceiptSink {
    fn existing_receipt(
        &self,
        correlation_id: &str,
        receipt: &AdapterOperationRecord,
    ) -> Result<Option<Digest>, AdapterError> {
        use rusqlite::OptionalExtension;
        let ledger = self.lock()?;
        let row: Option<(String, String, String)> = ledger.connection().query_row(
            "SELECT operation_id, receipt_json, receipt_digest FROM effect_receipts WHERE correlation_id = ?1",
            [correlation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| AdapterError::Receipt { detail: error.to_string() })?;
        let Some((operation_id, json, digest)) = row else {
            return Ok(None);
        };
        let value: Value = serde_json::from_str(&json).map_err(|error| AdapterError::Receipt {
            detail: error.to_string(),
        })?;
        let mut stored = AdapterOperationRecord::from_wire(&value["operation"])?;
        let canonical =
            odin_strict_json::canonicalize(&value).map_err(|error| AdapterError::Receipt {
                detail: error.to_string(),
            })?;
        if canonical != json.as_bytes() {
            return Err(AdapterError::Receipt {
                detail: "original receipt is not canonical".to_owned(),
            });
        }
        let actual = Digest::hash(json.as_bytes());
        if operation_id != receipt.operation_id.as_str() || actual.to_string() != digest {
            return Err(AdapterError::Receipt {
                detail: "original receipt identity or digest mismatch".to_owned(),
            });
        }
        if stored.state != crate::operation::OperationRecordState::Succeeded {
            return Ok(None);
        }
        if stored.output_digest.is_none()
            || value
                .pointer("/evidence/response_digest")
                .and_then(Value::as_str)
                != stored
                    .output_digest
                    .map(|digest| digest.to_string())
                    .as_deref()
        {
            return Err(AdapterError::Receipt {
                detail: "original receipt output evidence mismatch".to_owned(),
            });
        }
        if value.pointer("/evidence/kind").and_then(Value::as_str) != Some(stored.kind.as_str())
            || value.pointer("/evidence/adapter_identity")
                != Some(&serde_json::to_value(&stored.adapter).map_err(|error| {
                    AdapterError::Receipt {
                        detail: error.to_string(),
                    }
                })?)
        {
            return Err(AdapterError::Receipt {
                detail: "original receipt evidence identity mismatch".to_owned(),
            });
        }
        stored.output_digest = receipt.output_digest;
        if stored != *receipt {
            return Err(AdapterError::Receipt {
                detail: "original receipt does not match recovered operation".to_owned(),
            });
        }
        Ok(Some(actual))
    }

    fn persist_recovery_receipt(
        &self,
        correlation_id: &str,
        receipt: &AdapterOperationRecord,
        evidence: &Value,
    ) -> Result<Digest, AdapterError> {
        use rusqlite::OptionalExtension;
        receipt.validate()?;
        let envelope = serde_json::json!({"operation": receipt.to_wire(), "evidence": evidence});
        let bytes =
            odin_strict_json::canonicalize(&envelope).map_err(|error| AdapterError::Canonical {
                detail: error.to_string(),
            })?;
        let json = String::from_utf8(bytes).map_err(|error| AdapterError::Canonical {
            detail: error.to_string(),
        })?;
        let digest = Digest::hash(json.as_bytes());
        let at = encode_utc((self.clock)()).map_err(|error| AdapterError::Receipt {
            detail: error.to_string(),
        })?;
        let mut ledger = self.lock()?;
        ledger.with_tx(|tx| {
            tx.execute("INSERT INTO recovery_effect_receipts (correlation_id, operation_id, receipt_json, receipt_digest, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(correlation_id) DO NOTHING", [correlation_id, receipt.operation_id.as_str(), &json, &digest.to_string(), &at])?;
            let existing: Option<(String, String, String)> = tx.query_row("SELECT operation_id, receipt_json, receipt_digest FROM recovery_effect_receipts WHERE correlation_id = ?1", [correlation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?;
            let (operation_id, existing_json, stored_digest) = existing.ok_or_else(|| LedgerError::Conflict("recovery receipt missing".to_owned()))?;
            let stored: Value = serde_json::from_str(&existing_json).map_err(|error| LedgerError::Conflict(error.to_string()))?;
            let stored_record = AdapterOperationRecord::from_wire(&stored["operation"]).map_err(|error| LedgerError::Conflict(error.to_string()))?;
            let canonical = odin_strict_json::canonicalize(&stored).map_err(|error| LedgerError::Conflict(error.to_string()))?;
            if canonical != existing_json.as_bytes() || stored_record.output_digest.is_none() || stored.pointer("/evidence/response_digest").and_then(Value::as_str) != stored_record.output_digest.map(|digest| digest.to_string()).as_deref() {
                return Err(LedgerError::Conflict("invalid recovery receipt evidence".to_owned()));
            }
            let actual = Digest::hash(existing_json.as_bytes());
            if operation_id != receipt.operation_id.as_str() || stored_record != *receipt || actual.to_string() != stored_digest {
                return Err(LedgerError::Conflict("recovery receipt differs from recovered operation".to_owned()));
            }
            Ok(actual)
        }).map_err(|error| AdapterError::Receipt { detail: error.to_string() })
    }

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
