-- The keyword legs rank by BM25 (ParadeDB pg_search) instead of ts_rank over
-- tsvectors. pg_search is preloaded by the server (dotfiles
-- odin-foundations.nix) and created by the superuser unit odin-brain-db, so
-- the IF NOT EXISTS below only confirms it.
--
-- brain_search replaces brain_lex: one row per chunk with the item filter,
-- the chunk text the BM25 index reads, and the 256-d embedding prefix the
-- HNSW leg walks; nomination never reads brain_chunk's inlined 2048-d rows.
-- The statement triggers keep it aligned with brain_chunk.
--
-- Runs while it holds brain_chunk's writers (a few minutes at 4.3M chunks:
-- the HNSW build dominates). An embedding backfill writing meanwhile fails
-- its next statement and resumes on its next run; pause it during deploy.
CREATE EXTENSION IF NOT EXISTS pg_search;

SET LOCAL maintenance_work_mem = '4GB';
SET LOCAL max_parallel_maintenance_workers = 4;

LOCK TABLE brain_chunk IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE brain_search (
    id bigint GENERATED ALWAYS AS IDENTITY,
    generation_id text NOT NULL,
    ordinal bigint NOT NULL,
    item text NOT NULL,
    model text,
    text text NOT NULL,
    prefix halfvec(256),
    PRIMARY KEY (generation_id, ordinal)
);

INSERT INTO brain_search (generation_id, ordinal, item, model, text, prefix)
SELECT chunk.generation_id, chunk.ordinal, chunk.item, chunk.model, chunk.text, lex.prefix
FROM brain_chunk chunk
LEFT JOIN brain_lex lex USING (generation_id, ordinal);

DROP TRIGGER brain_lex_insert ON brain_chunk;
DROP TRIGGER brain_lex_delete ON brain_chunk;
DROP TRIGGER brain_lex_embed ON brain_chunk;
DROP FUNCTION brain_lex_insert();
DROP FUNCTION brain_lex_delete();
DROP FUNCTION brain_lex_embed();
DROP TABLE brain_lex;
-- The tsvector was only the old keyword leg's.
ALTER TABLE brain_chunk DROP COLUMN tsv;

CREATE FUNCTION brain_search_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO brain_search (generation_id, ordinal, item, model, text, prefix)
    SELECT generation_id, ordinal, item, model, text,
           CASE WHEN embedding IS NOT NULL
                THEN subvector(embedding, 1, 256)::halfvec(256)
           END
    FROM inserted
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER brain_search_insert
AFTER INSERT ON brain_chunk
REFERENCING NEW TABLE AS inserted
FOR EACH STATEMENT
EXECUTE FUNCTION brain_search_insert();

CREATE FUNCTION brain_search_delete() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    DELETE FROM brain_search AS search
    USING deleted
    WHERE search.generation_id = deleted.generation_id
      AND search.ordinal = deleted.ordinal;
    RETURN NULL;
END;
$$;

CREATE TRIGGER brain_search_delete
AFTER DELETE ON brain_chunk
REFERENCING OLD TABLE AS deleted
FOR EACH STATEMENT
EXECUTE FUNCTION brain_search_delete();

-- UPDATE OF is incompatible with transition tables, so every update resyncs
-- the prefix. The only writer is the embedding fill.
CREATE FUNCTION brain_search_embed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    UPDATE brain_search AS search
    SET model = updated.model,
        prefix = CASE WHEN updated.embedding IS NOT NULL
                      THEN subvector(updated.embedding, 1, 256)::halfvec(256)
                 END
    FROM updated
    WHERE search.generation_id = updated.generation_id
      AND search.ordinal = updated.ordinal;
    RETURN NULL;
END;
$$;

CREATE TRIGGER brain_search_embed
AFTER UPDATE ON brain_chunk
REFERENCING NEW TABLE AS updated
FOR EACH STATEMENT
EXECUTE FUNCTION brain_search_embed();

-- An addressed record reads its item's ordinals without walking the generation.
CREATE INDEX brain_search_item ON brain_search (generation_id, item);
-- The filtered HNSW walk of the vector leg; null prefixes are not indexed.
CREATE INDEX brain_search_prefix ON brain_search USING hnsw (prefix halfvec_cosine_ops);
-- The keyword leg: chunk text split at every non-alphanumeric character and
-- lowercased, unstemmed (names, course codes and ids match as written), as
-- rank::terms splits a query; generation and item are exact filter fields, so
-- a turn's served set and hidden items filter inside the index.
CREATE INDEX brain_search_bm25 ON brain_search
    USING bm25 (id, (text::pdb.simple), (generation_id::pdb.literal), (item::pdb.literal))
    WITH (key_field = 'id');

ANALYZE brain_search;

-- Curated records: `doc` is the text each row is found by (written by
-- brain-load), BM25-indexed in place of the tsvector and its hand-rolled idf.
-- People are found by every name, handle, email and phone; units and facts by
-- stemmed English. Assets are rewritten by brain-load's next run.
ALTER TABLE brain_person ADD COLUMN doc text NOT NULL DEFAULT '';
ALTER TABLE brain_unit ADD COLUMN doc text NOT NULL DEFAULT '';
ALTER TABLE brain_fact ADD COLUMN doc text NOT NULL DEFAULT '';
ALTER TABLE brain_asset ADD COLUMN doc text NOT NULL DEFAULT '';

UPDATE brain_person person
SET doc = coalesce((SELECT string_agg(handle.value, ' ' ORDER BY handle.value)
                    FROM brain_person_handle handle WHERE handle.slug = person.slug), person.name);
UPDATE brain_unit unit
SET doc = concat_ws(' ', unit.summary, array_to_string(unit.topics, ' '),
                    (SELECT string_agg(concat_ws(' ', who->>'name', who->>'handle', who->>'relations'), ' ')
                     FROM jsonb_array_elements(CASE jsonb_typeof(unit.people) WHEN 'array'
                                                    THEN unit.people ELSE '[]' END) who));
UPDATE brain_fact SET doc = concat_ws(' ', subject, text);
UPDATE brain_asset SET doc = concat_ws(' ', album, translate(path, '/_.-', '    '));

DROP INDEX brain_person_tsv;
DROP INDEX brain_unit_tsv;
DROP INDEX brain_fact_tsv;
DROP INDEX brain_asset_tsv;
ALTER TABLE brain_person DROP COLUMN tsv;
ALTER TABLE brain_unit DROP COLUMN tsv;
ALTER TABLE brain_fact DROP COLUMN tsv;
ALTER TABLE brain_asset DROP COLUMN tsv;

CREATE INDEX brain_person_bm25 ON brain_person USING bm25 (slug, (doc::pdb.simple)) WITH (key_field = 'slug');
CREATE INDEX brain_unit_bm25 ON brain_unit
    USING bm25 (unit_id, (doc::pdb.simple('stemmer=english'))) WITH (key_field = 'unit_id');
CREATE INDEX brain_fact_bm25 ON brain_fact
    USING bm25 (fact_id, (doc::pdb.simple('stemmer=english'))) WITH (key_field = 'fact_id');
CREATE INDEX brain_asset_bm25 ON brain_asset USING bm25 (path, (doc::pdb.simple)) WITH (key_field = 'path');

-- Never read: a topic filter is `= ANY (topics)`, and 125 channels are a
-- sequential scan.
DROP INDEX brain_unit_topics;
DROP INDEX brain_channel_name;
DROP INDEX brain_channel_server;
