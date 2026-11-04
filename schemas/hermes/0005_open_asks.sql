-- An open ask is a request of the owner whose delegated jobs all ended
-- without a delivered result. `job` is the newest job that ended unmet (live
-- memory shows the ask under it, with the notes pinned to that job).
CREATE TABLE open_asks (
    id TEXT PRIMARY KEY NOT NULL,
    subject TEXT NOT NULL,
    job TEXT NOT NULL,
    unmet TEXT NOT NULL,
    opened_ms INTEGER NOT NULL,
    next_wake_ms INTEGER NOT NULL
) STRICT;
