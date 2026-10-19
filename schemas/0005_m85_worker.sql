-- M8.5 worker: durable registry for transaction-qualified owned workers.
--
-- This migration creates the durable worker registry that records every
-- transient user scope the process WorkerAuthority owns. A worker row is the
-- transaction-qualified intent to run one `${TX_ID}-${WP_ID}-attempt-${ATTEMPT}-*`
-- transient user scope: the unit name is unique, the InvocationID is proven
-- from the user manager before any payload exec, and the cgroup path/inode and
-- leader PID/start identity are the residue-correlation anchors. State moves
-- through compare-and-set transitions shared with the domain vocabulary;
-- terminal rows (`stopped`, `failed`, `residual`) never move again, and
-- nonterminal rows survive restart so an interrupted authority can reconcile
-- by InvocationID against the live manager.
--
-- The migration runner owns schema_migrations rows and their canonical BLAKE3
-- checksums; this file is registered as built-in migration 5 with an
-- independent checksum constant in both odin-ledger and the registry
-- migration inventory.

CREATE TABLE worker_registry (
  worker_id TEXT PRIMARY KEY CHECK (worker_id <> ''),
  unit TEXT NOT NULL UNIQUE CHECK (unit <> '' AND unit LIKE '%.scope'),
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

CREATE INDEX worker_registry_correlation
  ON worker_registry (correlation_id, state);
