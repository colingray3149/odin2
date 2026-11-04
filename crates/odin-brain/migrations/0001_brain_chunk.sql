CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE brain_chunk (
    generation_id text NOT NULL,
    ordinal bigint NOT NULL,
    item text NOT NULL,
    digest text NOT NULL,
    text text NOT NULL,
    tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', text)) STORED,
    model text,
    embedding halfvec(2048),
    PRIMARY KEY (generation_id, ordinal),
    CHECK ((model IS NULL) = (embedding IS NULL))
);

CREATE INDEX brain_chunk_tsv ON brain_chunk USING gin (tsv);
-- The embedding model is Matryoshka-trained: its 256-dimension prefix nominates, the full vector scores.
CREATE INDEX brain_chunk_prefix ON brain_chunk
    USING hnsw ((subvector(embedding, 1, 256)::halfvec(256)) halfvec_cosine_ops);
CREATE INDEX brain_chunk_embedded_digest ON brain_chunk (model, digest) WHERE embedding IS NOT NULL;
CREATE INDEX brain_chunk_unembedded ON brain_chunk (generation_id, ordinal) WHERE embedding IS NULL;

CREATE TABLE brain_generation (
    owner text NOT NULL,
    generation_id text NOT NULL,
    PRIMARY KEY (owner, generation_id)
);

CREATE INDEX brain_generation_id ON brain_generation (generation_id);
