ALTER TABLE trusted_devices ADD COLUMN revoking_at INTEGER;

CREATE TABLE IF NOT EXISTS device_session_grants (
    token_id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;
CREATE INDEX IF NOT EXISTS device_session_grants_device
    ON device_session_grants(device_id, created_at, token_id);
