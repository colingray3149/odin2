-- M1 extends the canonical control-plane schema. The migration runner owns
-- schema_migrations rows and their canonical BLAKE3 checksums.
ALTER TABLE schema_migrations ADD COLUMN name TEXT;
ALTER TABLE schema_migrations ADD COLUMN checksum TEXT;

ALTER TABLE lanes ADD COLUMN status TEXT NOT NULL DEFAULT 'desired';
ALTER TABLE lanes ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE runs ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);

CREATE TABLE attempts (
  attempt_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
  status TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  executor_id TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (run_id, attempt_number)
) STRICT;

CREATE INDEX attempts_run_idx ON attempts(run_id, attempt_number);
CREATE INDEX attempts_status_idx ON attempts(status, updated_at);
CREATE INDEX lanes_status_idx ON lanes(status, updated_at);
CREATE INDEX runs_status_idx ON runs(status, updated_at);

ALTER TABLE commands ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE checkpoints ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE checkpoints ADD COLUMN committed_at TEXT;
ALTER TABLE checkpoints ADD COLUMN artifact_digest TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000';
ALTER TABLE incidents ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE approvals ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE artifacts ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
ALTER TABLE provider_leases ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);

CREATE INDEX checkpoints_rollback_idx ON checkpoints(rollback_of, created_at);
CREATE UNIQUE INDEX incidents_failure_signature_idx ON incidents(failure_signature);
CREATE UNIQUE INDEX provider_leases_one_active_lane_idx
  ON provider_leases(lane_id) WHERE ended_at IS NULL;
CREATE INDEX artifact_refs_object_idx ON artifact_refs(object_kind, object_id, relation);

CREATE TABLE idempotency_keys (
  key TEXT PRIMARY KEY,
  command_id TEXT NOT NULL UNIQUE,
  claimed_at TEXT NOT NULL
) STRICT;

CREATE TABLE events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  causation_id TEXT,
  actor_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
) STRICT;

CREATE INDEX events_correlation_idx ON events(correlation_id, sequence);
CREATE INDEX events_kind_idx ON events(kind, sequence);

CREATE TRIGGER events_immutable_update
BEFORE UPDATE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER events_immutable_delete
BEFORE DELETE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  actor_json TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  payload_json TEXT NOT NULL,
  redaction_json TEXT NOT NULL DEFAULT '{}',
  occurred_at TEXT NOT NULL
) STRICT;

CREATE INDEX audit_events_kind_idx ON audit_events(kind, sequence);
CREATE INDEX audit_events_occurred_idx ON audit_events(occurred_at, sequence);

CREATE TRIGGER audit_events_immutable_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are immutable');
END;

CREATE TRIGGER audit_events_immutable_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are immutable');
END;

ALTER TABLE live_sessions ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE live_sessions ADD COLUMN title_json TEXT;
ALTER TABLE live_sessions ADD COLUMN manifest_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE colin_devices ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE colin_devices ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE stream_cursors ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE stream_cursors ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE terminal_control_leases ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE terminal_control_leases ADD COLUMN row_revision INTEGER NOT NULL DEFAULT 0 CHECK (row_revision >= 0);
ALTER TABLE transfers ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE transfers ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE render_jobs ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE render_jobs ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0);

CREATE TABLE live_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES live_sessions(session_id),
  epoch INTEGER NOT NULL CHECK (epoch >= 1),
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  occurred_at TEXT NOT NULL,
  body_json TEXT NOT NULL,
  blob_refs_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE (session_id, sequence)
) STRICT;

CREATE INDEX live_events_session_epoch_idx
  ON live_events(session_id, epoch, sequence);

CREATE TRIGGER live_events_immutable_update
BEFORE UPDATE ON live_events
BEGIN
  SELECT RAISE(ABORT, 'live events are immutable');
END;

CREATE TRIGGER live_events_immutable_delete
BEFORE DELETE ON live_events
BEGIN
  SELECT RAISE(ABORT, 'live events are immutable');
END;

CREATE TABLE live_commands (
  command_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES live_sessions(session_id),
  expected_epoch INTEGER NOT NULL CHECK (expected_epoch >= 1),
  expected_event_head INTEGER CHECK (expected_event_head >= 0),
  body_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  completed_at TEXT,
  outcome_json TEXT
) STRICT;

CREATE INDEX live_commands_session_idx ON live_commands(session_id, issued_at);

CREATE TABLE live_metadata (
  session_id TEXT NOT NULL REFERENCES live_sessions(session_id),
  kind TEXT NOT NULL CHECK (kind IN ('terminal', 'file', 'render')),
  metadata_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (session_id, kind, metadata_key)
) STRICT;

CREATE INDEX live_metadata_updated_idx ON live_metadata(kind, updated_at);
