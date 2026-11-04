ALTER TABLE schedule_items ADD COLUMN routine_digest TEXT;
ALTER TABLE schedule_items ADD COLUMN dispatch_started INTEGER NOT NULL DEFAULT 0
    CHECK (dispatch_started IN (0, 1));

-- A legacy firing row may already have reached its recipient. Never claim
-- it was cancelled before dispatch merely because the old schema cannot tell.
UPDATE schedule_items SET dispatch_started = 1 WHERE status = 'firing';
