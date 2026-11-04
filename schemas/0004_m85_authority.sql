-- M8.5 authority: durable sole capability and operation authority.
--
-- This migration creates the durable operation journal the kernel operation
-- authority owns. Every capability invocation is prepared here before any
-- effect, transitions through canonical effect states under compare-and-set
-- guard, and never loses a nonterminal state — `in_doubt` rows survive restart
-- and block their correlation identity until reconciled. The legacy sidecar
-- JSON authority (OdinSidecarState/v2) is archived into this schema exactly
-- once, including a receipt for a zero-file source.
--
-- The migration runner owns schema_migrations rows and their canonical BLAKE3
-- checksums; this file is registered as built-in migration 4 with an
-- independent checksum constant in both odin-ledger and the registry
-- migration inventory.

CREATE TABLE operation_journal (
  correlation_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  capsule_id TEXT NOT NULL,
  seat_id TEXT NOT NULL,
  token_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  listing_digest TEXT NOT NULL,
  capability TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  request_json TEXT NOT NULL,
  effect_state TEXT NOT NULL CHECK (effect_state IN ('prepared', 'effect_started', 'committed', 'aborted', 'in_doubt')),
  reconciliation_json TEXT NOT NULL,
  evidence_digest TEXT,
  executor_id TEXT NOT NULL,
  prepared_binding TEXT NOT NULL,
  binding_digest TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX operation_journal_capsule
  ON operation_journal (capsule_id, effect_state);

CREATE TABLE capsule_lease (
  capsule_id TEXT PRIMARY KEY,
  seat_id TEXT NOT NULL,
  token_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  listing_digest TEXT NOT NULL,
  lease_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
  close_mode TEXT CHECK (close_mode IN ('drain', 'abort')),
  drained INTEGER NOT NULL DEFAULT 0 CHECK (drained >= 0),
  opened_at TEXT NOT NULL,
  closed_at TEXT CHECK ((state = 'closed') = (closed_at IS NOT NULL))
) STRICT;

CREATE TABLE stop_intent (
  correlation_id TEXT PRIMARY KEY,
  operation_id TEXT REFERENCES operation_journal(operation_id),
  seat_id TEXT NOT NULL,
  token_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  listing_digest TEXT NOT NULL,
  capsule_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('requested', 'stopped', 'failed')),
  evidence_json TEXT,
  requested_at TEXT NOT NULL,
  settled_at TEXT CHECK ((state IN ('stopped', 'failed')) = (settled_at IS NOT NULL))
) STRICT;

CREATE INDEX stop_intent_capsule ON stop_intent (capsule_id, state);

CREATE TABLE operation_usage (
  session_id TEXT PRIMARY KEY,
  requests INTEGER NOT NULL CHECK (requests >= 0),
  stops INTEGER NOT NULL CHECK (stops >= 0),
  spend INTEGER NOT NULL CHECK (spend >= 0),
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE authority_import (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  source_schema TEXT NOT NULL,
  source_sha256 TEXT,
  receipt_json TEXT NOT NULL,
  imported_operations INTEGER NOT NULL CHECK (imported_operations >= 0),
  imported_stops INTEGER NOT NULL CHECK (imported_stops >= 0),
  remapped_effect_started INTEGER NOT NULL CHECK (remapped_effect_started >= 0),
  zero_file INTEGER NOT NULL CHECK (zero_file IN (0, 1)),
  imported_at TEXT NOT NULL
) STRICT;

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

CREATE INDEX worker_stop_intent_correlation
  ON worker_stop_intent (correlation_id, state);
