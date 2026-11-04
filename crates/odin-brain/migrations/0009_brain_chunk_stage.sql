-- A streaming build's chunks wait here until its last chunk completes the
-- manifest that names their generation; then they move into brain_chunk and
-- brain_chunk_cite under that id. Unlogged: a crash loses only builds in
-- flight, which their store drops and rebuilds.
CREATE UNLOGGED TABLE brain_chunk_stage (
    stage text NOT NULL,
    ordinal bigint NOT NULL,
    chunk_id text NOT NULL,
    item text NOT NULL,
    trust text NOT NULL,
    digest text NOT NULL,
    text text NOT NULL,
    byte_start bigint NOT NULL,
    byte_end bigint NOT NULL,
    PRIMARY KEY (stage, ordinal)
);

-- A store's owner key is its directory now that no SQLite file sits in it.
UPDATE brain_generation SET owner = left(owner, -length('/brain-index.sqlite3'))
WHERE owner LIKE '%/brain-index.sqlite3';
