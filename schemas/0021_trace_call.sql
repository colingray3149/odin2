ALTER TABLE trace_calls ADD COLUMN call_id TEXT;

CREATE UNIQUE INDEX trace_calls_call_id
  ON trace_calls(session_id, call_id)
  WHERE call_id IS NOT NULL;

CREATE TABLE trace_blob_aliases (
  wire_sha256 TEXT PRIMARY KEY,
  digest TEXT NOT NULL REFERENCES trace_blobs(digest)
) STRICT;
