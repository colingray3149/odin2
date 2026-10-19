CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS schedule_items (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('notify', 'wake')),
    text TEXT NOT NULL,
    fire_at_ms INTEGER NOT NULL,
    anchor TEXT,
    created_at_ms INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'firing', 'fired', 'cancelled', 'failed')),
    fired_at_ms INTEGER,
    every_minutes INTEGER,
    repeats_left INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    retry_at_ms INTEGER,
    event INTEGER NOT NULL DEFAULT 0 CHECK (event IN (0, 1))
) STRICT;
CREATE INDEX IF NOT EXISTS schedule_items_pending
    ON schedule_items(fire_at_ms) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS schedule_items_firing
    ON schedule_items(retry_at_ms) WHERE status = 'firing';
CREATE INDEX IF NOT EXISTS schedule_items_fired_anchor
    ON schedule_items(anchor, fired_at_ms) WHERE status = 'fired';
CREATE INDEX IF NOT EXISTS schedule_items_settled
    ON schedule_items(fired_at_ms) WHERE status IN ('fired', 'cancelled', 'failed');

CREATE TABLE IF NOT EXISTS routine_state (
    routine TEXT PRIMARY KEY NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    fired_at_ms INTEGER,
    fired_occurrence TEXT
) STRICT;
