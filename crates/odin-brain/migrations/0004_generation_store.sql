-- A generation this store holds whole: the citation identity of every chunk,
-- the Atlas provenance of every item, and the header. The header is written
-- last, after the stored rows were read back and hashed to its manifest, so
-- a header row means the rows behind it are proven; serving reads only
-- generations that have one.

CREATE TABLE brain_chunk_cite (
    generation_id text NOT NULL,
    ordinal bigint NOT NULL,
    chunk_id text NOT NULL,
    trust text NOT NULL,
    byte_start bigint NOT NULL,
    byte_end bigint NOT NULL,
    PRIMARY KEY (generation_id, ordinal)
);

CREATE TABLE brain_item_provenance (
    generation_id text NOT NULL,
    item_id text NOT NULL,
    node_id text NOT NULL,
    path text NOT NULL,
    source_class text NOT NULL,
    scope_tags text[] NOT NULL,
    PRIMARY KEY (generation_id, item_id)
);

CREATE TABLE brain_generation_header (
    generation_id text PRIMARY KEY,
    atlas_id text NOT NULL,
    atlas_revision text NOT NULL,
    chunker_version text NOT NULL,
    tokenizer text NOT NULL,
    embedding_model text NOT NULL,
    manifest_digest text NOT NULL,
    created_epoch bigint NOT NULL,
    chunk_count bigint NOT NULL
);

CREATE INDEX brain_generation_header_pin
    ON brain_generation_header (atlas_id, atlas_revision, embedding_model, created_epoch DESC);

-- An addressed record reads its item's ordinals without walking the generation.
CREATE INDEX brain_lex_item ON brain_lex (generation_id, item);
