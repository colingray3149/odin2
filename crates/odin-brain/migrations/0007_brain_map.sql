-- The brain map, written by brain-load and brain-reduce: units and photos
-- carry the people they resolve to (brain_person slugs), Discord channels and
-- projects are rows, and topics link to projects. The topic tables were
-- created by brain-reduce-knowledge before; IF NOT EXISTS keeps that data.

ALTER TABLE brain_unit ADD COLUMN persons text[] NOT NULL DEFAULT '{}', ADD COLUMN channel_id text;
CREATE INDEX brain_unit_persons ON brain_unit USING gin (persons);
CREATE INDEX brain_unit_channel ON brain_unit (channel_id, last_ts);
ALTER TABLE brain_asset ADD COLUMN persons text[] NOT NULL DEFAULT '{}';
CREATE INDEX brain_asset_persons ON brain_asset USING gin (persons);

-- A Discord channel or thread (parent: its category, or a thread's channel)
-- or a direct-message conversation (no server).
CREATE TABLE brain_channel (
    channel_id text PRIMARY KEY,
    server_id text,
    server text,
    name text NOT NULL,
    kind text NOT NULL,
    parent_id text,
    parent text
);
CREATE INDEX brain_channel_server ON brain_channel (lower(server));
CREATE INDEX brain_channel_name ON brain_channel (lower(name));

-- projects.toml, with an embedding of its name and description.
CREATE TABLE brain_project (
    project_id text PRIMARY KEY,
    name text NOT NULL,
    parent text,
    description text NOT NULL,
    places text[] NOT NULL,
    embedding halfvec(256)
);

CREATE TABLE IF NOT EXISTS brain_topic (topic_id text PRIMARY KEY, name text NOT NULL, aliases text[] NOT NULL,
    unit_count int NOT NULL, first_ts timestamptz, last_ts timestamptz, local_only bool NOT NULL, embedding halfvec(256));
CREATE TABLE IF NOT EXISTS brain_topic_unit (topic_id text NOT NULL, unit_id text NOT NULL, PRIMARY KEY (topic_id, unit_id));
CREATE INDEX IF NOT EXISTS brain_topic_unit_unit ON brain_topic_unit (unit_id);
-- how: reviewed, place (most of the topic's units sit in a project's Discord place), nearest (a tagged topic is close), described (the project description is).
CREATE TABLE IF NOT EXISTS brain_topic_project (topic_id text PRIMARY KEY, project_id text NOT NULL, how text NOT NULL);
CREATE INDEX IF NOT EXISTS brain_topic_project_project ON brain_topic_project (project_id);
CREATE TABLE IF NOT EXISTS brain_fact_group (group_id text PRIMARY KEY, text text NOT NULL, subject text NOT NULL,
    valid_from timestamptz, fact_ids text[] NOT NULL, unit_ids text[] NOT NULL, sources text[] NOT NULL, local_only bool NOT NULL);
CREATE TABLE IF NOT EXISTS brain_event (group_id text PRIMARY KEY, month date NOT NULL, topic_ids text[] NOT NULL);
