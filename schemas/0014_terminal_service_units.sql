-- Migration 14: the terminal sandbox's transient service units join the
-- durable worker registry.
--
-- The worker registry is the one stop-authority surface: one unit, one
-- durable stop handle, proofs anchored to the manager's InvocationID. A
-- terminal sandbox is a systemd-run transient `.service`, never a scope:
-- the route's filesystem confinement (NoNewPrivileges, PrivateTmp,
-- ProtectHome/ProtectSystem, Bind/Inaccessible paths) is exec context a
-- scope unit cannot carry, and the tmux server must be born inside it.
-- The registry's unit column therefore admits exactly that namespace —
-- `odin-term-*.service` — beside the worker scopes it has always owned;
-- every other service name stays refused.
--
-- The table is rebuilt in place because SQLite cannot alter a CHECK
-- constraint. Rows are carried across explicitly — every column verbatim —
-- through foreign-key-free staging, so each statement is individually
-- foreign-key clean and the commit never depends on deferred constraint
-- counters: the child is recreated against the renamed parent and refilled
-- before the transaction commits.
--
-- The migration runner owns schema_migrations rows and their canonical
-- BLAKE3 checksums; this file is registered as built-in migration 14 with
-- an independent checksum constant in both odin-ledger and the registry
-- migration inventory.
CREATE TABLE worker_registry_current (
  worker_id TEXT PRIMARY KEY CHECK (worker_id <> ''),
  unit TEXT NOT NULL UNIQUE CHECK (
    unit <> '' AND (unit LIKE '%.scope' OR unit LIKE 'odin-term-%.service')
  ),
  invocation_id TEXT UNIQUE
    CHECK (
      invocation_id IS NULL OR
      (length(invocation_id) = 32 AND invocation_id NOT GLOB '*[^0-9a-f]*')
    ),
  correlation_id TEXT NOT NULL CHECK (correlation_id <> ''),
  tx_id TEXT NOT NULL CHECK (tx_id <> ''),
  wp_id TEXT NOT NULL CHECK (wp_id <> ''),
  attempt INTEGER NOT NULL CHECK (attempt >= 0),
  cgroup_path TEXT CHECK (cgroup_path IS NULL OR cgroup_path LIKE '/%'),
  cgroup_inode INTEGER CHECK (cgroup_inode IS NULL OR cgroup_inode > 0),
  leader_pid INTEGER CHECK (leader_pid IS NULL OR leader_pid > 0),
  leader_start_ticks INTEGER
    CHECK (leader_start_ticks IS NULL OR leader_start_ticks > 0),
  state TEXT NOT NULL CHECK (state IN ('registered', 'scope_created', 'payload_running', 'stopped', 'failed', 'residual')),
  residue_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (
    (
      invocation_id IS NULL AND cgroup_path IS NULL AND cgroup_inode IS NULL AND
      leader_pid IS NULL AND leader_start_ticks IS NULL
    ) OR (
      invocation_id IS NOT NULL AND cgroup_path IS NOT NULL AND
      cgroup_inode IS NOT NULL AND leader_pid IS NOT NULL AND
      leader_start_ticks IS NOT NULL
    )
  ),
  CHECK (
    state IN ('registered', 'failed') OR invocation_id IS NOT NULL
  )
) STRICT;
INSERT INTO worker_registry_current
  SELECT worker_id,unit,invocation_id,correlation_id,tx_id,wp_id,attempt,
         cgroup_path,cgroup_inode,leader_pid,leader_start_ticks,state,
         residue_json,created_at,updated_at
  FROM worker_registry;
CREATE TABLE worker_stop_intent_staging (
  worker_id TEXT PRIMARY KEY,
  correlation_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('requested', 'stopped', 'failed')),
  evidence_json TEXT NOT NULL CHECK (evidence_json <> ''),
  attempts INTEGER NOT NULL CHECK (attempts >= 0),
  requested_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT CHECK ((state IN ('stopped', 'failed')) = (settled_at IS NOT NULL))
) STRICT;
INSERT INTO worker_stop_intent_staging
  SELECT worker_id,correlation_id,state,evidence_json,attempts,requested_at,
         updated_at,settled_at
  FROM worker_stop_intent;
DROP TABLE worker_stop_intent;
DROP TABLE worker_registry;
ALTER TABLE worker_registry_current RENAME TO worker_registry;
CREATE TABLE worker_stop_intent (
  worker_id TEXT PRIMARY KEY REFERENCES worker_registry(worker_id),
  correlation_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('requested', 'stopped', 'failed')),
  evidence_json TEXT NOT NULL CHECK (evidence_json <> ''),
  attempts INTEGER NOT NULL CHECK (attempts >= 0),
  requested_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT CHECK ((state IN ('stopped', 'failed')) = (settled_at IS NOT NULL))
) STRICT;
INSERT INTO worker_stop_intent
  SELECT worker_id,correlation_id,state,evidence_json,attempts,requested_at,
         updated_at,settled_at
  FROM worker_stop_intent_staging;
DROP TABLE worker_stop_intent_staging;
CREATE INDEX worker_registry_correlation
  ON worker_registry (correlation_id, state);
CREATE INDEX worker_stop_intent_correlation
  ON worker_stop_intent (correlation_id, state);
