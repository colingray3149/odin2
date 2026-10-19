-- Curated brain records: people, their handles, curated conversation
-- units with facts and evidence lines, and the photo/document index.
-- Written by odin-brain/scripts/brain-load (incremental, idempotent) and
-- read by the seat `brain` tool. `local_only` comes from schema/brain.toml's
-- local_only_paths; `secret` names the secret rule a unit's text matched.
-- Both are enforced on every read by a cloud model lane; a fact inherits
-- its unit's secret finding.

CREATE TABLE brain_person (
    slug text PRIMARY KEY,
    name text NOT NULL,
    record jsonb NOT NULL,
    first_contact timestamptz,
    last_contact timestamptz,
    source_path text NOT NULL,
    local_only boolean NOT NULL,
    tsv tsvector NOT NULL
);
CREATE INDEX brain_person_tsv ON brain_person USING gin (tsv);

CREATE TABLE brain_person_handle (
    slug text NOT NULL REFERENCES brain_person ON DELETE CASCADE,
    kind text NOT NULL,
    source text NOT NULL,
    value text NOT NULL,
    PRIMARY KEY (slug, kind, source, value)
);
CREATE INDEX brain_person_handle_value ON brain_person_handle (lower(value));

CREATE TABLE brain_unit (
    unit_id text PRIMARY KEY,
    source text NOT NULL,
    sha256 text NOT NULL,
    summary text NOT NULL,
    topics text[] NOT NULL,
    people jsonb NOT NULL,
    first_ts timestamptz,
    last_ts timestamptz,
    source_path text NOT NULL,
    local_only boolean NOT NULL,
    secret text,
    embedding halfvec(256),
    tsv tsvector NOT NULL
);
CREATE INDEX brain_unit_tsv ON brain_unit USING gin (tsv);
CREATE INDEX brain_unit_source_time ON brain_unit (source, last_ts);
CREATE INDEX brain_unit_topics ON brain_unit USING gin (topics);

CREATE TABLE brain_fact (
    fact_id text PRIMARY KEY,
    unit_id text NOT NULL REFERENCES brain_unit ON DELETE CASCADE,
    subject text NOT NULL,
    text text NOT NULL,
    when_text text NOT NULL,
    valid_from timestamptz,
    valid_to timestamptz,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    local_only boolean NOT NULL,
    embedding halfvec(256),
    tsv tsvector NOT NULL
);
CREATE INDEX brain_fact_tsv ON brain_fact USING gin (tsv);
CREATE INDEX brain_fact_unit ON brain_fact (unit_id);
CREATE INDEX brain_fact_subject ON brain_fact (lower(subject));

CREATE TABLE brain_fact_evidence (
    fact_id text NOT NULL REFERENCES brain_fact ON DELETE CASCADE,
    message_id text NOT NULL,
    ts timestamptz,
    author text NOT NULL,
    text text NOT NULL,
    PRIMARY KEY (fact_id, message_id)
);

CREATE TABLE brain_asset (
    path text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('photo', 'doc')),
    sha256 text NOT NULL,
    dated timestamptz,
    place jsonb,
    album text,
    size bigint,
    local_only boolean NOT NULL,
    tsv tsvector NOT NULL
);
CREATE INDEX brain_asset_tsv ON brain_asset USING gin (tsv);
CREATE INDEX brain_asset_dated ON brain_asset (kind, dated);
