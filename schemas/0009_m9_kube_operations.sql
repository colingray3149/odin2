CREATE TABLE kube_job_runs (
  run_id TEXT PRIMARY KEY,
  cluster TEXT NOT NULL,
  namespace TEXT NOT NULL,
  launch_json TEXT NOT NULL CHECK (json_valid(launch_json)),
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE kube_job_operations (
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
  UNIQUE (run_id, kind, idempotency_digest),
  CHECK ((state = 'pending' AND result_json IS NULL AND failure_kind IS NULL AND failure_reason IS NULL)
      OR (state = 'applied' AND result_json IS NOT NULL AND failure_kind IS NULL AND failure_reason IS NULL)
      OR (state = 'rejected' AND result_json IS NULL AND failure_kind IS NOT NULL AND failure_reason IS NOT NULL))
) STRICT;

CREATE INDEX kube_pending_operations ON kube_job_operations(cluster, namespace, created_at)
  WHERE state = 'pending';

CREATE TABLE kube_projection_revisions (
  object_key TEXT PRIMARY KEY,
  content_digest TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE kube_job_attempts (
  attempt_id INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL,
  canonical_operation_id TEXT REFERENCES kube_job_operations(operation_id),
  request_fingerprint TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('requested','replayed','conflict','applied','rejected')),
  reason TEXT,
  created_at TEXT NOT NULL
) STRICT;
