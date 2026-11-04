-- An unknown delivery must leave `firing`. SQLite cannot alter a CHECK,
-- so the table is rebuilt with `uncertain` admitted and the same columns.
CREATE TABLE schedule_items_new (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('notify', 'wake')),
    text TEXT NOT NULL,
    fire_at_ms INTEGER NOT NULL,
    anchor TEXT,
    created_at_ms INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'firing', 'fired', 'cancelled', 'failed', 'uncertain')),
    fired_at_ms INTEGER,
    every_minutes INTEGER,
    repeats_left INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    retry_at_ms INTEGER,
    event INTEGER NOT NULL DEFAULT 0 CHECK (event IN (0, 1)),
    routine_digest TEXT,
    dispatch_started INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_started IN (0, 1))
) STRICT;

INSERT INTO schedule_items_new (
    id, kind, text, fire_at_ms, anchor, created_at_ms, status, fired_at_ms,
    every_minutes, repeats_left, attempts, retry_at_ms, event, routine_digest,
    dispatch_started
)
SELECT
    id, kind, text, fire_at_ms, anchor, created_at_ms, status, fired_at_ms,
    every_minutes, repeats_left, attempts, retry_at_ms, event, routine_digest,
    dispatch_started
FROM schedule_items;

DROP TABLE schedule_items;
ALTER TABLE schedule_items_new RENAME TO schedule_items;

CREATE INDEX schedule_items_pending
    ON schedule_items(fire_at_ms) WHERE status = 'pending';
CREATE INDEX schedule_items_firing
    ON schedule_items(retry_at_ms) WHERE status = 'firing';
CREATE INDEX schedule_items_fired_anchor
    ON schedule_items(anchor, fired_at_ms) WHERE status = 'fired';
CREATE INDEX schedule_items_settled
    ON schedule_items(fired_at_ms) WHERE status IN ('fired', 'cancelled', 'failed', 'uncertain');
CREATE INDEX schedule_items_settled_deadline
    ON schedule_items(fire_at_ms)
    WHERE status IN ('fired', 'cancelled', 'failed', 'uncertain') AND fired_at_ms IS NULL;
