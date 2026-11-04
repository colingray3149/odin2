CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id TEXT PRIMARY KEY NOT NULL,
    tailnet_node_id TEXT NOT NULL,
    label TEXT NOT NULL,
    credential_digest BLOB NOT NULL CHECK(length(credential_digest) = 32),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    revoked_at INTEGER
) STRICT;
CREATE INDEX IF NOT EXISTS trusted_devices_created_at
    ON trusted_devices(created_at, device_id);
