CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL
) STRICT;

CREATE TABLE campaigns (
    id TEXT PRIMARY KEY NOT NULL,
    args TEXT NOT NULL
);
CREATE TABLE campaign_reservations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    request TEXT NOT NULL,
    core_hours REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'refunded', 'settled')),
    actual_core_hours REAL
);
CREATE INDEX campaign_reservations_campaign ON campaign_reservations(campaign_id);
