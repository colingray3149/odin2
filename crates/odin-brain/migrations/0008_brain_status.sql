-- The brain pipeline's status: scripts/brain-status writes it, brain-load loads it
-- each hour, the brain tool's op=status reads it. One JSON document per scope.
CREATE TABLE brain_status (
    scope text PRIMARY KEY,
    doc jsonb NOT NULL,
    loaded timestamptz NOT NULL
);
