-- M1 compatibility: retire the legacy M1 `state` enums that migration 0002
-- superseded with canonical `status` columns, and repair the zero artifact
-- digests that 0002 defaulted onto pre-M1 checkpoints. The migration runner
-- owns schema_migrations rows and their canonical BLAKE3 checksums.
--
-- Only legacy rows still carrying the 0002 default status are mapped: a row
-- whose status was already written by post-M2 code is preserved verbatim.
-- Every mapping is derived from the row's own legacy `state` value; nothing is
-- synthesized.

UPDATE lanes SET status = CASE state
  WHEN 'desired' THEN 'desired'
  WHEN 'provisioning' THEN 'provisioning'
  WHEN 'ready' THEN 'ready'
  WHEN 'running' THEN 'running'
  WHEN 'waiting_approval' THEN 'waitingApproval'
  WHEN 'paused' THEN 'paused'
  WHEN 'recovering' THEN 'recovering'
  WHEN 'completed' THEN 'succeeded'
  WHEN 'failed' THEN 'failed'
  WHEN 'blocked' THEN 'blocked'
  WHEN 'cancelled' THEN 'cancelled'
END
WHERE status = 'desired';

UPDATE runs SET status = CASE state
  WHEN 'desired' THEN 'pending'
  WHEN 'provisioning' THEN 'planning'
  WHEN 'ready' THEN 'planning'
  WHEN 'running' THEN 'running'
  WHEN 'waiting_approval' THEN 'waitingApproval'
  WHEN 'paused' THEN 'paused'
  WHEN 'recovering' THEN 'recovering'
  WHEN 'completed' THEN 'succeeded'
  WHEN 'failed' THEN 'failed'
  WHEN 'blocked' THEN 'blocked'
  WHEN 'cancelled' THEN 'cancelled'
END
WHERE status = 'pending';

-- A checkpoint still carrying the 0002 zero digest is repaired only from the
-- canonical digest of the artifact it references. A checkpoint whose artifact
-- ref has no artifacts row is an orphan: the subquery yields NULL, the NOT NULL
-- constraint on artifact_digest aborts the statement, and the migration (and
-- its whole transaction) rolls back.
UPDATE checkpoints
SET artifact_digest = (
  SELECT artifacts.content_digest
  FROM artifacts
  WHERE artifacts.artifact_ref = checkpoints.artifact_ref
)
WHERE artifact_digest = '0000000000000000000000000000000000000000000000000000000000000000';

-- The legacy columns are dead after the mapping above; only the canonical
-- status columns remain.
ALTER TABLE lanes DROP COLUMN state;
ALTER TABLE runs DROP COLUMN state;
