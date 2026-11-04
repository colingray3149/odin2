-- The lexical leg tokenizes like rank::terms: ASCII alphanumeric runs, lowercased, nothing stemmed or dropped
-- (the english parser kept paths, URLs and e-mail addresses whole and dropped stop words).
DROP INDEX brain_chunk_tsv;
ALTER TABLE brain_chunk DROP COLUMN tsv;
ALTER TABLE brain_chunk ADD COLUMN tsv tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', regexp_replace(text, '[^A-Za-z0-9]+', ' ', 'g'))) STORED;
CREATE INDEX brain_chunk_tsv ON brain_chunk USING gin (tsv);
