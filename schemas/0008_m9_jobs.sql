-- M9 jobs: durable registry, stop intents, and evidence for external
-- Kubernetes Job workers.
--
-- The kernel StopAuthority owns the sole destructive surface for Job workers.
-- A Job worker row records the real cluster/namespace/name/UID binding proved
-- by the Job owner before any payload can run: the workload is created
-- suspended, its UID observed from the API, and only a durably registered
-- binding may later be released through the authority. The UID is the opaque
-- Kubernetes domain value and carries no assumed layout; only nonemptiness
-- and a bounded length are enforced. No systemd unit, PID, or cgroup value is
-- ever recorded for a Job worker; the process worker registry stays the sole
-- home of Linux scope identity.
--
-- One Kubernetes Job identity backs at most one worker that is not proved
-- cleanly gone: a fresh incarnation (new minted WorkerId, same Job UID —
-- e.g. resume of a suspended Job) may register only after every prior
-- worker for that identity reached `stopped`. `failed` and `residual` rows
-- still block a new incarnation — their cleanup was never proved — and
-- terminal rows are preserved forever.
--
-- The stop action is chosen by the user per stop and durably bound on the
-- stop intent, never preselected at registration: the same running worker
-- supports Pause(Suspend) and Cancel(Delete) alike. `job_stop_intent`
-- mirrors `worker_stop_intent`: the authority journals the requested verdict
-- before any backend actuation, a pending intent may be re-bound to the
-- other action before it settles, every indeterminate attempt replaces the
-- pending evidence and increments `attempts`, and only proved evidence
-- settles to a terminal state. Terminal rows never move.
--
-- The migration runner owns schema_migrations rows and their canonical BLAKE3
-- checksums; this file is registered as built-in migration 8 with an
-- independent checksum constant in odin-ledger.

CREATE TABLE job_worker_registry (
  worker_id TEXT PRIMARY KEY CHECK (worker_id <> ''),
  backend TEXT NOT NULL CHECK (backend = 'kube.job'),
  cluster TEXT NOT NULL CHECK (cluster <> ''),
  namespace TEXT NOT NULL CHECK (namespace <> ''),
  job_name TEXT NOT NULL CHECK (job_name <> ''),
  job_uid TEXT NOT NULL CHECK (length(job_uid) BETWEEN 1 AND 128),
  correlation_id TEXT NOT NULL CHECK (correlation_id <> ''),
  operation_id TEXT NOT NULL CHECK (operation_id <> ''),
  state TEXT NOT NULL CHECK (
    state IN ('registered', 'released', 'stopping', 'stopped', 'failed', 'residual')
  ),
  residue_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

-- One Kubernetes Job identity backs at most one worker not proved stopped;
-- a fresh incarnation may register only once the prior worker proved
-- stopped with no surviving pods, and failed/residual rows still block.
CREATE UNIQUE INDEX job_worker_live_identity
  ON job_worker_registry (cluster, namespace, job_name, job_uid)
  WHERE state <> 'stopped';
CREATE INDEX job_worker_registry_correlation
  ON job_worker_registry (correlation_id, state);

CREATE TABLE job_stop_intent (
  worker_id TEXT PRIMARY KEY CHECK (worker_id <> ''),
  correlation_id TEXT NOT NULL CHECK (correlation_id <> ''),
  action TEXT NOT NULL CHECK (action IN ('delete', 'suspend')),
  state TEXT NOT NULL CHECK (state IN ('requested', 'stopped', 'failed')),
  evidence_json TEXT NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts >= 0),
  requested_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT CHECK ((state = 'requested') = (settled_at IS NULL))
) STRICT;
CREATE INDEX job_stop_intent_correlation
  ON job_stop_intent (correlation_id, state);
