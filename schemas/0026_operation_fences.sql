-- Persistent generations fence stale operation owners after crash or takeover.
CREATE TABLE operation_fences (
  correlation_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL CHECK (generation > 0)
) STRICT;
