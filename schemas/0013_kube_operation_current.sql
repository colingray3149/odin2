-- Migration 13: one current operation per kube job operation family.
--
-- The (run_id, kind, idempotency_digest) tuple stops being owned forever
-- by whichever row claimed it first. A proved rejection is history, not a
-- current operation: it must never absorb a fresh operation id, and the
-- table-level UNIQUE that pinned every state to one row per tuple is
-- replaced by a partial unique index over the current (pending or
-- applied) operation only. Proved rejections stay as immutable
-- provenance rows, and a fresh id re-presenting the same command is
-- admitted as its own pending attempt instead of inheriting the old
-- verdict. Journal admission still proves content identity only: the
-- fresh kernel-approved permit the caller consumes above the journal
-- remains the admission authority.
--
-- The table is rebuilt in place because SQLite cannot drop a
-- table-level UNIQUE constraint. The attempt rows are carried across
-- explicitly — every column, id, and verdict verbatim — through a
-- foreign-key-free staging copy, so each statement of the rebuild is
-- individually foreign-key clean and the commit never depends on
-- deferred constraint counters: the child is recreated against the
-- renamed parent and refilled before the transaction commits.
CREATE TABLE kube_job_operations_current (
  operation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  cluster TEXT NOT NULL,
  namespace TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('create','pause','resume','restart','cancel','summarize')),
  idempotency_digest TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  request_json TEXT NOT NULL CHECK (json_valid(request_json)),
  progress_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(progress_json)),
  state TEXT NOT NULL CHECK (state IN ('pending','applied','rejected')),
  result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
  failure_kind TEXT,
  failure_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK ((state = 'pending' AND result_json IS NULL AND failure_kind IS NULL AND failure_reason IS NULL)
      OR (state = 'applied' AND result_json IS NOT NULL AND failure_kind IS NULL AND failure_reason IS NULL)
      OR (state = 'rejected' AND result_json IS NULL AND failure_kind IS NOT NULL AND failure_reason IS NOT NULL))
) STRICT;
INSERT INTO kube_job_operations_current
  SELECT operation_id,run_id,cluster,namespace,kind,idempotency_digest,
         fingerprint,request_json,progress_json,state,result_json,
         failure_kind,failure_reason,created_at,updated_at
  FROM kube_job_operations;
CREATE TABLE kube_job_attempts_staging (
  attempt_id INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL,
  canonical_operation_id TEXT,
  request_fingerprint TEXT NOT NULL,
  verdict TEXT NOT NULL,
  reason TEXT,
  created_at TEXT NOT NULL
) STRICT;
INSERT INTO kube_job_attempts_staging
  SELECT attempt_id,operation_id,canonical_operation_id,request_fingerprint,
         verdict,reason,created_at
  FROM kube_job_attempts;
DROP TABLE kube_job_attempts;
DROP TABLE kube_job_operations;
ALTER TABLE kube_job_operations_current RENAME TO kube_job_operations;
CREATE TABLE kube_job_attempts (
  attempt_id INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL,
  canonical_operation_id TEXT REFERENCES kube_job_operations(operation_id),
  request_fingerprint TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('requested','replayed','conflict','applied','rejected')),
  reason TEXT,
  created_at TEXT NOT NULL
) STRICT;
INSERT INTO kube_job_attempts
  SELECT attempt_id,operation_id,canonical_operation_id,request_fingerprint,
         verdict,reason,created_at
  FROM kube_job_attempts_staging;
DROP TABLE kube_job_attempts_staging;
-- The durable alias mapping is read per admission: a covering
-- operation_id-leading index keeps that lookup direct instead of
-- scanning the full attempt history.
CREATE INDEX kube_job_attempt_alias
  ON kube_job_attempts(operation_id, canonical_operation_id);
CREATE INDEX kube_pending_operations ON kube_job_operations(cluster, namespace, created_at)
  WHERE state = 'pending';
CREATE UNIQUE INDEX kube_job_operation_current
  ON kube_job_operations(run_id, kind, idempotency_digest)
  WHERE state IN ('pending', 'applied');
