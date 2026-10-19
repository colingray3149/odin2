CREATE TABLE pod_worker_registry (
  worker_id TEXT PRIMARY KEY CHECK (worker_id <> ''),
  backend TEXT NOT NULL DEFAULT 'kube.pod' CHECK (backend = 'kube.pod'),
  cluster TEXT NOT NULL CHECK (cluster <> ''),
  namespace TEXT NOT NULL CHECK (namespace <> ''),
  pod_name TEXT NOT NULL CHECK (pod_name <> ''),
  pod_uid TEXT CHECK (pod_uid IS NULL OR pod_uid <> ''),
  policy_name TEXT NOT NULL CHECK (policy_name <> ''),
  policy_uid TEXT CHECK (policy_uid IS NULL OR policy_uid <> ''),
  correlation_id TEXT NOT NULL CHECK (correlation_id <> ''),
  state TEXT NOT NULL CHECK (state IN ('registered', 'released', 'stopping', 'stopped')),
  stop_audit_json TEXT CHECK (stop_audit_json IS NULL OR json_valid(stop_audit_json)),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  requested_at TEXT,
  settled_at TEXT,
  CHECK (state <> 'released' OR (pod_uid IS NOT NULL AND policy_uid IS NOT NULL)),
  CHECK (state NOT IN ('stopping', 'stopped') OR (requested_at IS NOT NULL AND stop_audit_json IS NOT NULL)),
  CHECK ((state = 'stopped') = (settled_at IS NOT NULL))
) STRICT;

-- The operator's Pod stop demand is journaled on its own row before any
-- backend actuation and settles only on proved complete-absence evidence:
-- every indeterminate attempt replaces the pending evidence and increments
-- `attempts`, and an ambiguous verdict leaves the demand durably requested.
CREATE TABLE pod_stop_intent (
  worker_id TEXT PRIMARY KEY CHECK (worker_id <> ''),
  correlation_id TEXT NOT NULL CHECK (correlation_id <> ''),
  action TEXT NOT NULL CHECK (action = 'delete'),
  state TEXT NOT NULL CHECK (state IN ('requested', 'stopped')),
  evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
  attempts INTEGER NOT NULL CHECK (attempts >= 0),
  requested_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT CHECK ((state = 'requested') = (settled_at IS NULL))
) STRICT;
CREATE INDEX pod_stop_intent_correlation
  ON pod_stop_intent (correlation_id, state);

CREATE UNIQUE INDEX pod_worker_active_correlation
  ON pod_worker_registry (correlation_id) WHERE state <> 'stopped';
CREATE UNIQUE INDEX pod_worker_active_pod
  ON pod_worker_registry (cluster, namespace, pod_name) WHERE state <> 'stopped';
CREATE UNIQUE INDEX pod_worker_active_policy
  ON pod_worker_registry (cluster, namespace, policy_name) WHERE state <> 'stopped';
