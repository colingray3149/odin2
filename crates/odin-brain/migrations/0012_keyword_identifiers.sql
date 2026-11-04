-- Sinmara's retrieval investigation found that pdb.simple keeps a compact
-- alphanumeric identifier in one token, while spacing splits it. Use the same
-- alphabetic/numeric runs as retrieval::rank::terms on every keyword leg.
-- This only rebuilds keyword indexes in the existing Postgres store: chunk
-- text, generation ownership, embeddings and visibility fields are unchanged.
-- Keep 0011 immutable because existing stores validate applied checksums.
SET LOCAL maintenance_work_mem = '4GB';
SET LOCAL max_parallel_maintenance_workers = 4;

DROP INDEX brain_search_bm25;
CREATE INDEX brain_search_bm25 ON brain_search
    USING bm25 (id, (text::pdb.regex_pattern('\p{Alphabetic}+|\p{Number}+')),
                (generation_id::pdb.literal), (item::pdb.literal))
    WITH (key_field = 'id');

DROP INDEX brain_person_bm25;
CREATE INDEX brain_person_bm25 ON brain_person
    USING bm25 (slug, (doc::pdb.regex_pattern('\p{Alphabetic}+|\p{Number}+')))
    WITH (key_field = 'slug');
DROP INDEX brain_unit_bm25;
CREATE INDEX brain_unit_bm25 ON brain_unit
    USING bm25 (unit_id, (doc::pdb.regex_pattern('\p{Alphabetic}+|\p{Number}+', 'stemmer=english')))
    WITH (key_field = 'unit_id');
DROP INDEX brain_fact_bm25;
CREATE INDEX brain_fact_bm25 ON brain_fact
    USING bm25 (fact_id, (doc::pdb.regex_pattern('\p{Alphabetic}+|\p{Number}+', 'stemmer=english')))
    WITH (key_field = 'fact_id');
DROP INDEX brain_asset_bm25;
CREATE INDEX brain_asset_bm25 ON brain_asset
    USING bm25 (path, (doc::pdb.regex_pattern('\p{Alphabetic}+|\p{Number}+')))
    WITH (key_field = 'path');
