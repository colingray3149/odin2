CREATE INDEX IF NOT EXISTS schedule_items_settled_deadline
    ON schedule_items(fire_at_ms)
    WHERE status IN ('fired', 'cancelled', 'failed') AND fired_at_ms IS NULL;
