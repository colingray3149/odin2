-- M8.5 effect receipts: bounded canonical observations from the real effector.
--
-- The sidecar inserts one immutable receipt after the compiled effect has
-- returned measured output and before OperationAuthority settles the operation.
-- The journal binds receipt_digest as its evidence_digest; trusted readers
-- re-check correlation, operation id, canonical bytes, and both digest copies.

CREATE TABLE effect_receipts (
  correlation_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  receipt_digest TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;
