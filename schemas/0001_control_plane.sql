PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS registry_revisions (
  revision_id TEXT PRIMARY KEY,
  source_commit TEXT,
  content_hash TEXT NOT NULL UNIQUE,
  loaded_at TEXT NOT NULL,
  valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
  errors_json TEXT NOT NULL DEFAULT '[]'
) STRICT;

CREATE TABLE IF NOT EXISTS desired_objects (
  object_kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  revision_id TEXT NOT NULL REFERENCES registry_revisions(revision_id),
  schema_version INTEGER NOT NULL,
  definition_json TEXT NOT NULL,
  active INTEGER NOT NULL CHECK (active IN (0, 1)),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (object_kind, object_id)
) STRICT;

CREATE TABLE IF NOT EXISTS lanes (
  lane_id TEXT PRIMARY KEY,
  seat_id TEXT NOT NULL,
  project_id TEXT,
  template_id TEXT NOT NULL,
  backend TEXT NOT NULL CHECK (backend IN ('local_omp', 'local_worker', 'k3s', 'browser', 'research', 'slurm')),
  state TEXT NOT NULL CHECK (state IN ('desired', 'provisioning', 'ready', 'running', 'waiting_approval', 'paused', 'recovering', 'completed', 'failed', 'blocked', 'cancelled')),
  desired_revision INTEGER NOT NULL DEFAULT 1,
  current_run_id TEXT,
  session_ref TEXT,
  provider_lease_id TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  retained INTEGER NOT NULL DEFAULT 1 CHECK (retained IN (0, 1))
) STRICT;

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  lane_id TEXT NOT NULL REFERENCES lanes(lane_id),
  attempt_number INTEGER NOT NULL,
  workflow_id TEXT,
  workflow_version INTEGER,
  state TEXT NOT NULL CHECK (state IN ('desired', 'provisioning', 'ready', 'running', 'waiting_approval', 'paused', 'recovering', 'completed', 'failed', 'blocked', 'cancelled')),
  input_hash TEXT NOT NULL,
  accepted_capability_revision TEXT,
  lease_id TEXT,
  absolute_deadline TEXT,
  retry_budget INTEGER NOT NULL DEFAULT 0,
  retries_used INTEGER NOT NULL DEFAULT 0,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (lane_id, attempt_number)
) STRICT;

CREATE TABLE IF NOT EXISTS arms (
  arm_id TEXT PRIMARY KEY,
  parent_run_id TEXT NOT NULL REFERENCES runs(run_id),
  lane_id TEXT NOT NULL REFERENCES lanes(lane_id),
  role TEXT NOT NULL,
  result_schema_ref TEXT NOT NULL,
  capability_set_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  ended_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS plans (
  run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
  revision INTEGER NOT NULL,
  objective TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS plan_items (
  run_id TEXT NOT NULL REFERENCES plans(run_id) ON DELETE CASCADE,
  item_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'blocked', 'completed', 'cancelled')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (run_id, item_id),
  UNIQUE (run_id, ordinal)
) STRICT;

CREATE TABLE IF NOT EXISTS commands (
  command_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  correlation_id TEXT NOT NULL,
  causation_id TEXT,
  issuer TEXT NOT NULL,
  approval_id TEXT,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_version INTEGER NOT NULL,
  arguments_hash TEXT NOT NULL,
  arguments_json TEXT NOT NULL,
  expected_desired_revision INTEGER,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  accepted_at TEXT,
  terminal_status TEXT CHECK (terminal_status IN ('completed', 'failed', 'blocked', 'cancelled', 'expired', 'rejected')),
  terminal_result_json TEXT,
  terminal_at TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS commands_target_idx ON commands(target_kind, target_id, issued_at);
CREATE INDEX IF NOT EXISTS commands_correlation_idx ON commands(correlation_id);

CREATE TABLE IF NOT EXISTS command_attempts (
  attempt_id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL REFERENCES commands(command_id),
  executor_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  state TEXT NOT NULL,
  started_at TEXT NOT NULL,
  last_progress_at TEXT,
  ended_at TEXT,
  error_class TEXT,
  error_json TEXT,
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE (command_id, attempt_number)
) STRICT;

CREATE TABLE IF NOT EXISTS leases (
  lease_id TEXT PRIMARY KEY,
  object_kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_heartbeat_at TEXT NOT NULL,
  last_useful_progress_at TEXT NOT NULL,
  released_at TEXT,
  UNIQUE (object_kind, object_id, revision)
) STRICT;

CREATE INDEX IF NOT EXISTS leases_active_idx ON leases(object_kind, object_id, expires_at, released_at);

CREATE TABLE IF NOT EXISTS heartbeats (
  heartbeat_id TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL REFERENCES leases(lease_id),
  observed_at TEXT NOT NULL,
  health_json TEXT NOT NULL,
  useful_progress INTEGER NOT NULL CHECK (useful_progress IN (0, 1)),
  progress_marker TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  command_id TEXT REFERENCES commands(command_id),
  compatibility_key TEXT NOT NULL,
  artifact_ref TEXT NOT NULL,
  state_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  committed INTEGER NOT NULL DEFAULT 0 CHECK (committed IN (0, 1)),
  rollback_of TEXT REFERENCES checkpoints(checkpoint_id)
) STRICT;

CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(run_id),
  severity TEXT NOT NULL,
  confidence_micros INTEGER NOT NULL CHECK (confidence_micros >= 0 AND confidence_micros <= 1000000),
  deviation TEXT NOT NULL,
  failure_signature TEXT NOT NULL,
  expected_state_json TEXT NOT NULL,
  observed_state_json TEXT NOT NULL,
  affected_objects_json TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL,
  allowed_capabilities_json TEXT NOT NULL,
  attempt_ids_json TEXT NOT NULL DEFAULT '[]',
  recommended_next_action TEXT NOT NULL,
  escalation_target TEXT NOT NULL,
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  last_useful_progress_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('open', 'recovering', 'escalated', 'resolved', 'blocked'))
) STRICT;

CREATE INDEX IF NOT EXISTS incidents_status_idx ON incidents(status, severity, last_observed_at);

CREATE TABLE IF NOT EXISTS repair_proposals (
  repair_proposal_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
  target_project_id TEXT NOT NULL,
  target_revision TEXT NOT NULL,
  failure_signature TEXT NOT NULL,
  requested_behavior TEXT NOT NULL,
  risk_json TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL,
  affected_workflows_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('proposed', 'awaiting_dispatch', 'dispatched', 'implementing', 'canary', 'accepted', 'rejected', 'rolled_back', 'superseded')),
  dispatched_lane_id TEXT REFERENCES lanes(lane_id),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (incident_id, target_project_id, target_revision, failure_signature)
) STRICT;

CREATE INDEX IF NOT EXISTS repair_proposals_status_idx ON repair_proposals(status, target_project_id, updated_at);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('requested', 'approved', 'denied', 'expired', 'consumed', 'cancelled')),
  issuer TEXT NOT NULL,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  arguments_hash TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  consumed_by_command_id TEXT REFERENCES commands(command_id),
  decision_evidence_ref TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS approvals_open_idx ON approvals(status, expires_at);

CREATE TABLE IF NOT EXISTS provider_leases (
  provider_lease_id TEXT PRIMARY KEY,
  lane_id TEXT NOT NULL REFERENCES lanes(lane_id),
  provider_id TEXT NOT NULL,
  account_handle TEXT NOT NULL,
  model TEXT NOT NULL,
  role TEXT NOT NULL,
  affinity_key TEXT NOT NULL,
  quota_snapshot_json TEXT NOT NULL,
  selection_reason TEXT NOT NULL,
  predecessor_id TEXT REFERENCES provider_leases(provider_lease_id),
  started_at TEXT NOT NULL,
  expires_at TEXT,
  ended_at TEXT,
  end_reason TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS provider_leases_lane_idx ON provider_leases(lane_id, started_at);

CREATE TABLE IF NOT EXISTS context_bundles (
  bundle_id TEXT PRIMARY KEY,
  seat_id TEXT NOT NULL,
  project_id TEXT,
  lane_id TEXT NOT NULL REFERENCES lanes(lane_id),
  run_id TEXT REFERENCES runs(run_id),
  session_id TEXT NOT NULL,
  turn_id TEXT NOT NULL,
  model TEXT NOT NULL,
  tokenizer_id TEXT NOT NULL,
  seat_revision TEXT NOT NULL,
  slice_revision TEXT NOT NULL,
  capability_listing_digest TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  source_revisions_json TEXT NOT NULL,
  task_hash TEXT NOT NULL,
  model_context_limit INTEGER NOT NULL,
  token_budget INTEGER NOT NULL,
  token_estimate INTEGER NOT NULL,
  canonical_content BLOB NOT NULL,
  manifest_json TEXT NOT NULL,
  excluded_reasons_json TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS learning_proposals (
  proposal_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  state TEXT NOT NULL CHECK (state IN ('draft', 'validated', 'canary_pending', 'canary_active', 'accepted', 'rejected', 'rolled_back')),
  candidate_json TEXT NOT NULL,
  evidence_refs_json TEXT NOT NULL,
  source_trust TEXT NOT NULL CHECK (source_trust IN ('control', 'curated', 'observed', 'untrusted')),
  requested_trust TEXT NOT NULL CHECK (requested_trust IN ('control', 'curated', 'observed', 'untrusted')),
  baseline_atlas_revision TEXT NOT NULL,
  canary_policy_json TEXT NOT NULL,
  rollback_plan_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_ref TEXT PRIMARY KEY,
  content_digest TEXT NOT NULL UNIQUE,
  size_bytes INTEGER NOT NULL,
  media_type TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  retention_class TEXT NOT NULL CHECK (retention_class IN ('canonical', 'pinned', 'regenerable', 'scratch')),
  created_at TEXT NOT NULL,
  verified_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_refs (
  artifact_ref TEXT NOT NULL REFERENCES artifacts(artifact_ref),
  object_kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (artifact_ref, object_kind, object_id, relation)
) STRICT;

CREATE TABLE IF NOT EXISTS materialized_status (
  object_kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status_json TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  stale_after TEXT,
  PRIMARY KEY (object_kind, object_id)
) STRICT;

CREATE TABLE IF NOT EXISTS outbox (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  subject TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  published_at TEXT,
  publish_attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(published_at, sequence);

CREATE TABLE IF NOT EXISTS inbox_dedup (
  consumer_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  received_at TEXT NOT NULL,
  processed_at TEXT,
  result_hash TEXT,
  PRIMARY KEY (consumer_id, message_id)
) STRICT;

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE IF NOT EXISTS live_sessions (
  session_id TEXT PRIMARY KEY,
  seat_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  slice_id TEXT NOT NULL,
  lane_id TEXT NOT NULL REFERENCES lanes(lane_id),
  target_node_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  epoch INTEGER NOT NULL DEFAULT 1 CHECK (epoch >= 1),
  event_head INTEGER NOT NULL DEFAULT 0 CHECK (event_head >= 0),
  terminal_head INTEGER NOT NULL DEFAULT 0 CHECK (terminal_head >= 0),
  open_tab INTEGER NOT NULL CHECK (open_tab IN (0, 1)),
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  retired_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS colin_devices (
  device_id TEXT PRIMARY KEY,
  tailnet_node_id TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  credential_digest TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS stream_cursors (
  device_id TEXT NOT NULL REFERENCES colin_devices(device_id),
  stream_id TEXT NOT NULL,
  acknowledged_sequence INTEGER NOT NULL CHECK (acknowledged_sequence >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (device_id, stream_id)
) STRICT;

CREATE TABLE IF NOT EXISTS terminal_control_leases (
  lease_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES live_sessions(session_id),
  device_id TEXT NOT NULL REFERENCES colin_devices(device_id),
  pane_ref TEXT NOT NULL,
  revision INTEGER NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  released_at TEXT,
  UNIQUE (session_id, revision)
) STRICT;

CREATE TABLE IF NOT EXISTS transfers (
  transfer_id TEXT PRIMARY KEY,
  session_id TEXT REFERENCES live_sessions(session_id),
  device_id TEXT NOT NULL REFERENCES colin_devices(device_id),
  source_json TEXT NOT NULL,
  target_json TEXT NOT NULL,
  media_type TEXT NOT NULL,
  byte_len INTEGER NOT NULL CHECK (byte_len >= 0),
  chunk_len INTEGER NOT NULL CHECK (chunk_len > 0),
  content_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('declared','receiving','verified','published','rejected','cancelled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS render_jobs (
  render_id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL UNIQUE REFERENCES commands(command_id),
  source_json TEXT NOT NULL,
  source_digest TEXT NOT NULL,
  renderer_id TEXT NOT NULL,
  renderer_version TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled')),
  progress_micros INTEGER NOT NULL DEFAULT 0 CHECK (progress_micros BETWEEN 0 AND 1000000),
  output_artifact_ref TEXT REFERENCES artifacts(artifact_ref),
  failure_evidence_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS live_sessions_lane_idx ON live_sessions(lane_id, state, updated_at);
CREATE INDEX IF NOT EXISTS transfers_state_idx ON transfers(state, updated_at);
CREATE INDEX IF NOT EXISTS render_jobs_state_idx ON render_jobs(state, updated_at);
