CREATE TABLE approval_owner_decisions (
  approval_id TEXT PRIMARY KEY REFERENCES approvals(approval_id),
  consumer_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  arguments_hash TEXT NOT NULL,
  decision_revision INTEGER NOT NULL CHECK(decision_revision >= 2),
  decided_by TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  FOREIGN KEY (consumer_id, message_id) REFERENCES inbox_dedup(consumer_id, message_id)
) STRICT;
