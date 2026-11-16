-- Recovery evidence supplements, and never overwrites, the original attempt evidence.
ALTER TABLE operation_journal ADD COLUMN recovery_evidence_digest TEXT;

CREATE TABLE recovery_effect_receipts (
    correlation_id TEXT PRIMARY KEY NOT NULL,
    operation_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
