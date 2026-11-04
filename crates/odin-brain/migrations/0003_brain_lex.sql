-- Nomination must not read brain_chunk: each heap tuple inlines a 2048-d
-- embedding (~5 KB) next to the tsvector, so a lexical rank or a filtered
-- prefix walk pulls pages it does not score. brain_lex keeps the lexical
-- tsvector, the item filter, and the 256-d prefix the vector leg orders by.
-- Statement triggers keep it aligned with brain_chunk; the backfill holds
-- writers so a concurrent delete cannot leave an orphan lex row.

CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE TABLE brain_lex (
    generation_id text NOT NULL,
    ordinal bigint NOT NULL,
    item text NOT NULL,
    model text,
    tsv tsvector NOT NULL,
    prefix halfvec(256),
    PRIMARY KEY (generation_id, ordinal)
);

CREATE FUNCTION brain_lex_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO brain_lex (generation_id, ordinal, item, model, tsv, prefix)
    SELECT generation_id, ordinal, item, model, tsv,
           CASE WHEN embedding IS NOT NULL
                THEN subvector(embedding, 1, 256)::halfvec(256)
           END
    FROM inserted
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER brain_lex_insert
AFTER INSERT ON brain_chunk
REFERENCING NEW TABLE AS inserted
FOR EACH STATEMENT
EXECUTE FUNCTION brain_lex_insert();

CREATE FUNCTION brain_lex_delete() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    DELETE FROM brain_lex AS lex
    USING deleted
    WHERE lex.generation_id = deleted.generation_id
      AND lex.ordinal = deleted.ordinal;
    RETURN NULL;
END;
$$;

CREATE TRIGGER brain_lex_delete
AFTER DELETE ON brain_chunk
REFERENCING OLD TABLE AS deleted
FOR EACH STATEMENT
EXECUTE FUNCTION brain_lex_delete();

CREATE FUNCTION brain_lex_embed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    UPDATE brain_lex AS lex
    SET model = updated.model,
        prefix = CASE WHEN updated.embedding IS NOT NULL
                      THEN subvector(updated.embedding, 1, 256)::halfvec(256)
                 END
    FROM updated
    WHERE lex.generation_id = updated.generation_id
      AND lex.ordinal = updated.ordinal;
    RETURN NULL;
END;
$$;

-- UPDATE OF is incompatible with transition tables, so every update resyncs
-- the prefix. The only writer is the embedding fill.
CREATE TRIGGER brain_lex_embed
AFTER UPDATE ON brain_chunk
REFERENCING NEW TABLE AS updated
FOR EACH STATEMENT
EXECUTE FUNCTION brain_lex_embed();

LOCK TABLE brain_chunk IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO brain_lex (generation_id, ordinal, item, model, tsv, prefix)
SELECT generation_id, ordinal, item, model, tsv,
       CASE WHEN embedding IS NOT NULL
            THEN subvector(embedding, 1, 256)::halfvec(256)
       END
FROM brain_chunk
ON CONFLICT DO NOTHING;

-- generation_id equality plus tsv @@ in one index, so a turn does not union
-- posting lists for generations it is not serving.
CREATE INDEX brain_lex_tsv ON brain_lex USING gin (generation_id, tsv);

-- Filtered HNSW walks this prefix, not brain_chunk, so a graph visit does
-- not pull the inlined 2048-d embedding. Null prefixes are not indexed.
CREATE INDEX brain_lex_prefix ON brain_lex USING hnsw (prefix halfvec_cosine_ops);

ANALYZE brain_lex;

-- Nomination no longer reads these. Keeping them made every mirror maintain
-- a corpus-wide GIN and a second 456 MB HNSW graph for no query.
DROP INDEX brain_chunk_tsv;
DROP INDEX brain_chunk_prefix;
