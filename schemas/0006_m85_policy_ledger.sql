-- M8.5 registry policy accounting and monotonic logical-time authority.
-- Existing migration bytes remain frozen; all new authority is additive here.

CREATE TABLE budget_accounts (
  scope TEXT NOT NULL,
  window_start INTEGER NOT NULL CHECK (window_start >= 0),
  window_end INTEGER NOT NULL CHECK (window_end > window_start),
  policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
  policy_digest TEXT NOT NULL,
  limit_usd_micros INTEGER NOT NULL CHECK (limit_usd_micros > 0),
  reserved_usd_micros INTEGER NOT NULL DEFAULT 0 CHECK (reserved_usd_micros >= 0),
  reconciled_usd_micros INTEGER NOT NULL DEFAULT 0 CHECK (reconciled_usd_micros >= 0),
  status TEXT NOT NULL CHECK (status IN ('eligible', 'exhausted')),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  PRIMARY KEY (scope, window_start, policy_digest)
) STRICT;

CREATE TABLE budget_reservations (
  reservation_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  window_start INTEGER NOT NULL CHECK (window_start >= 0),
  policy_digest TEXT NOT NULL,
  reserved_usd_micros INTEGER NOT NULL CHECK (reserved_usd_micros > 0),
  reconciled_usd_micros INTEGER CHECK (reconciled_usd_micros >= 0),
  state TEXT NOT NULL CHECK (state IN ('reserved', 'reconciled')),
  created_logical INTEGER NOT NULL CHECK (created_logical >= 0),
  reconciled_logical INTEGER CHECK (reconciled_logical >= created_logical),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  FOREIGN KEY (scope, window_start, policy_digest)
    REFERENCES budget_accounts(scope, window_start, policy_digest)
) STRICT;

CREATE INDEX budget_reservations_account
  ON budget_reservations(scope, window_start, policy_digest, state);

ALTER TABLE leases ADD COLUMN acquired_logical INTEGER NOT NULL DEFAULT 0 CHECK (acquired_logical >= 0);
ALTER TABLE leases ADD COLUMN expires_logical INTEGER NOT NULL DEFAULT 1 CHECK (expires_logical > acquired_logical);
ALTER TABLE leases ADD COLUMN last_heartbeat_logical INTEGER NOT NULL DEFAULT 0 CHECK (last_heartbeat_logical >= acquired_logical);
ALTER TABLE leases ADD COLUMN last_useful_progress_logical INTEGER NOT NULL DEFAULT 0 CHECK (last_useful_progress_logical >= acquired_logical);
ALTER TABLE leases ADD COLUMN released_logical INTEGER CHECK (released_logical >= last_heartbeat_logical AND released_logical >= last_useful_progress_logical);

ALTER TABLE heartbeats ADD COLUMN observed_logical INTEGER NOT NULL DEFAULT 0 CHECK (observed_logical >= 0);

ALTER TABLE provider_leases ADD COLUMN started_logical INTEGER NOT NULL DEFAULT 0 CHECK (started_logical >= 0);
ALTER TABLE provider_leases ADD COLUMN expires_logical INTEGER CHECK (expires_logical > started_logical);
ALTER TABLE provider_leases ADD COLUMN ended_logical INTEGER CHECK (ended_logical >= started_logical);

ALTER TABLE incidents ADD COLUMN recovery_policy_revision INTEGER NOT NULL DEFAULT 0 CHECK (recovery_policy_revision >= 0);
ALTER TABLE incidents ADD COLUMN recovery_policy_digest TEXT NOT NULL DEFAULT 'blake3:0000000000000000000000000000000000000000000000000000000000000000';
