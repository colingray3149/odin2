CREATE TABLE trace_blobs (
  digest TEXT PRIMARY KEY,
  wire_sha256 TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  body_json TEXT NOT NULL
) STRICT;

CREATE TABLE trace_calls (
  session_id TEXT NOT NULL,
  entry_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  provider TEXT,
  model TEXT,
  api TEXT,
  skeleton_json TEXT NOT NULL,
  request_id TEXT,
  response_id TEXT,
  tool_ids_json TEXT NOT NULL DEFAULT '[]',
  trace_error TEXT,
  PRIMARY KEY (session_id, entry_id)
) STRICT;

CREATE TABLE trace_cursors (
  session_id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0)
) STRICT;
