//! Curated brain records (migrations 0005, 0007 and 0011, written by the brain
//! repo's `scripts/brain-load` and `brain-reduce`): people and their
//! handles, curated conversation units, facts with their evidence lines, the
//! photo/doc index, and the map joining them: the people a unit or photo
//! resolves to, its Discord channel, and the projects its topics belong to.
//! Each row's `doc` is the text it is found by, ranked by BM25.
//!
//! Every read takes `local`: whether the caller's model lane is declared
//! local. Rows under brain.toml's `local_only_paths` are served only then;
//! units with a secret finding (and their facts) are never served. Search
//! filters gated rows out and says whether any matched; a read by id names
//! why it was withheld.

use serde_json::Value;
use sqlx::Row;

use super::BrainPostgres;
use crate::error::{postgres_outage, BrainResult};

/// Facet filters of a record search. Dates are `YYYY-MM-DD`.
#[derive(Clone, Debug, Default)]
pub struct RecordFilters {
    /// `unit`, `fact`, `person`, `photo` or `doc`.
    pub kind: Option<String>,
    pub person: Option<String>,
    pub source: Option<String>,
    pub topic: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// Ranked hits and whether gated rows also matched the query.
#[derive(Clone, Debug)]
pub struct RecordHits {
    pub hits: Vec<Value>,
    pub withheld: bool,
}

/// One record read by id.
#[derive(Clone, Debug, PartialEq)]
pub enum RecordRead {
    Found(Value),
    Withheld(String),
    Missing,
}

/// Rows whose source path brain.toml declares local-only.
fn local_only_reason(id: &str, path: &str) -> String {
    format!(
        "{id} is local_only (brain.toml local_only_paths covers {path}); \
         only a local model lane may read it"
    )
}

fn secret_reason(id: &str, rule: &str) -> String {
    format!("{id} carries a secret finding ({rule}); it never leaves the local brain")
}

fn parse(text: String) -> BrainResult<Value> {
    serde_json::from_str(&text).map_err(|error| postgres_outage(format!("record JSON: {error}")))
}

const FACT_JSON: &str =
    "jsonb_build_object('kind', 'fact', 'id', f.fact_id, 'subject', f.subject, \
     'text', f.text, 'when', f.when_text, 'validFrom', f.valid_from, 'validTo', f.valid_to, \
     'recordedAt', f.recorded_at, 'unit', f.unit_id, 'source', u.source, 'title', u.title, \
     'from', u.first_ts, 'to', u.last_ts, 'evidence', \
     coalesce((SELECT jsonb_agg(jsonb_build_object('id', e.message_id, 'ts', e.ts, \
     'author', e.author, 'text', e.text) ORDER BY e.ts) FROM brain_fact_evidence e \
     WHERE e.fact_id = f.fact_id), '[]'))";

const UNIT_JSON: &str = "jsonb_build_object('kind', 'unit', 'id', u.unit_id, 'source', u.source, \
     'title', u.title, 'summary', u.summary, 'topics', u.topics, 'people', u.people, \
     'from', u.first_ts, 'to', u.last_ts)";

const PERSON_JSON: &str = "jsonb_build_object('kind', 'person', 'id', p.slug, 'name', p.name, \
     'firstContact', p.first_contact, 'lastContact', p.last_contact) || (p.record - 'slug')";

const ASSET_JSON: &str = "jsonb_build_object('kind', a.kind, 'id', a.path, 'album', a.album, \
     'dated', a.dated, 'place', a.place, 'size', a.size)";

/// The slugs a person key names: a slug, or an exact name, handle, email,
/// phone or photo-library person id, given as SQL parameter `param`.
fn person_slugs(param: &str) -> String {
    format!(
        "SELECT slug FROM brain_person WHERE slug = {param} \
         UNION SELECT slug FROM brain_person_handle WHERE lower(value) = lower({param})"
    )
}

/// The map around the servable units in CTE `s` (`$2`: local lane, `$3`:
/// list length): how many per source, the latest, and the people, projects
/// and Discord places they share; `exclude` is a slug expression the people
/// list leaves out (the person the map is about).
fn map_json(exclude: &str) -> String {
    format!(
        "jsonb_build_object('units', (SELECT count(*) FROM s), \
         'sources', coalesce((SELECT jsonb_object_agg(source, n) FROM \
             (SELECT source, count(*) AS n FROM s GROUP BY source) c), '{{}}'), \
         'recent', coalesce((SELECT jsonb_agg(x ORDER BY x->>'to' DESC NULLS LAST) FROM \
             (SELECT {UNIT_JSON} AS x FROM s u ORDER BY u.last_ts DESC NULLS LAST LIMIT $3) r), '[]'), \
         'people', coalesce((SELECT jsonb_agg(jsonb_build_object('id', p.slug, 'name', p.name, 'units', c.n) \
                 ORDER BY c.n DESC, p.slug) \
             FROM (SELECT slug, count(*) AS n FROM s, unnest(s.persons) AS slug \
                   WHERE slug IS DISTINCT FROM {exclude} GROUP BY slug ORDER BY n DESC, slug LIMIT $3) c \
             JOIN brain_person p USING (slug) WHERE NOT p.local_only OR $2), '[]'), \
         'projects', coalesce((SELECT jsonb_agg(jsonb_build_object('id', b.project_id, 'name', b.name, 'units', c.n) \
                 ORDER BY c.n DESC, b.project_id) \
             FROM (SELECT tp.project_id, count(DISTINCT tu.unit_id) AS n FROM s \
                   JOIN brain_topic_unit tu USING (unit_id) JOIN brain_topic_project tp USING (topic_id) \
                   GROUP BY tp.project_id ORDER BY n DESC, tp.project_id LIMIT $3) c \
             JOIN brain_project b USING (project_id)), '[]'), \
         'places', coalesce((SELECT jsonb_agg(jsonb_build_object('id', ch.channel_id, 'server', ch.server, \
                 'channel', ch.name, 'kind', ch.kind, 'parent', ch.parent, 'units', c.n) ORDER BY c.n DESC, ch.channel_id) \
             FROM (SELECT channel_id, count(*) AS n FROM s WHERE channel_id IS NOT NULL \
                   GROUP BY channel_id ORDER BY n DESC, channel_id LIMIT $3) c \
             JOIN brain_channel ch USING (channel_id)), '[]'))"
    )
}

/// Units a cloud lane may read (`$2`: the caller's lane is local).
const SERVABLE: &str = "(NOT u.local_only OR $2) AND u.secret IS NULL";

/// Several rows share the key: their ids and names, to read one by id.
fn candidates(rows: &[sqlx::postgres::PgRow]) -> RecordRead {
    RecordRead::Found(serde_json::json!({
        "candidates": rows.iter().map(|row| serde_json::json!({
            "id": row.get::<String, _>(0),
            "name": row.get::<Option<String>, _>(1),
        })).collect::<Vec<_>>(),
        "note": "several match; read one by its id",
    }))
}

/// Candidates each unit and fact leg, and each person and asset leg, nominates.
const TEXT_LEG: u32 = 40;
const NAME_LEG: u32 = 20;
/// The most people one name lookup lists as candidates.
const MATCHES: u32 = 20;

/// One keyword leg: up to `limit` rows of `table` (key `id`) matching the
/// query `$1` by BM25 among the filtered rows of CTE `rows`, best first.
fn keyword_leg(kind: &str, table: &str, id: &str, rows: &str, limit: u32) -> String {
    format!(
        "(SELECT '{kind}' AS k, {id} AS id, row_number() OVER (ORDER BY pdb.score({id}) DESC, {id}) AS r \
           FROM {table} WHERE $1 <> '' AND doc ||| $1 AND {id} IN (SELECT {id} FROM {rows}) \
           ORDER BY 3 LIMIT {limit})"
    )
}

/// The query text a record search matches: its keyword terms, space-joined
/// (empty when it has none).
fn keyword_text(query: &str) -> String {
    super::keyword_terms(query).join(" ")
}

impl BrainPostgres {
    /// Hybrid search over units, facts, people and assets: BM25 keyword
    /// legs and, given a query embedding, 256-d cosine candidates, fused by
    /// reciprocal rank.
    pub fn search_records(
        &self,
        query: &str,
        embedding: Option<Vec<f32>>,
        filters: &RecordFilters,
        local: bool,
        limit: i64,
    ) -> BrainResult<RecordHits> {
        let terms = keyword_text(query);
        if let Some(dims) = &embedding {
            super::check_dims(&"query embedding", dims)?;
        }
        let embedding = embedding.map(|mut dims| {
            dims.truncate(super::PREFIX_DIMS);
            dims
        });
        let filters = filters.clone();
        let sql = format!(
            "WITH q AS (SELECT $2::real[]::halfvec({prefix_dims}) AS v), \
             who AS (SELECT coalesce(array_agg(slug), '{{}}') AS slugs FROM ({who}) m), \
             units AS (SELECT u.* FROM brain_unit u WHERE (NOT u.local_only OR $9) AND u.secret IS NULL \
                 AND ($3::text IS NULL OR $3 = 'unit') AND ($5::text IS NULL OR u.source = $5) \
                 AND ($6::text IS NULL OR $6 = ANY (u.topics)) AND ($4::text IS NULL OR u.persons && (SELECT slugs FROM who) OR u.people::text ILIKE '%' || $4 || '%') \
                 AND ($7::date IS NULL OR u.last_ts >= $7::date) AND ($8::date IS NULL OR u.first_ts < $8::date + 1)), \
             facts AS (SELECT f.* FROM brain_fact f JOIN brain_unit u USING (unit_id) \
                 WHERE (NOT f.local_only OR $9) AND u.secret IS NULL \
                 AND ($3::text IS NULL OR $3 = 'fact') AND ($5::text IS NULL OR u.source = $5) \
                 AND ($6::text IS NULL OR $6 = ANY (u.topics)) \
                 AND ($4::text IS NULL OR f.subject ILIKE '%' || $4 || '%' OR u.persons && (SELECT slugs FROM who) \
                      OR u.people::text ILIKE '%' || $4 || '%') \
                 AND ($7::date IS NULL OR coalesce(f.valid_from, u.last_ts) >= $7::date) \
                 AND ($8::date IS NULL OR coalesce(f.valid_from, u.first_ts) < $8::date + 1)), \
             people AS (SELECT p.* FROM brain_person p WHERE (NOT p.local_only OR $9) \
                 AND ($3::text IS NULL OR $3 = 'person') AND $5::text IS NULL AND $6::text IS NULL \
                 AND ($4::text IS NULL OR p.slug IN (SELECT unnest(slugs) FROM who) OR p.doc &&& $4)), \
             assets AS (SELECT a.* FROM brain_asset a WHERE (NOT a.local_only OR $9) \
                 AND ($3::text IS NULL OR $3 = a.kind) AND ($4::text IS NULL OR a.persons && (SELECT slugs FROM who)) \
                 AND $5::text IS NULL AND $6::text IS NULL \
                 AND ($7::date IS NULL OR a.dated >= $7::date) AND ($8::date IS NULL OR a.dated < $8::date + 1)), \
             ranked AS ( \
               {unit_lexical} \
               UNION ALL (SELECT 'unit', unit_id, row_number() OVER (ORDER BY embedding <=> q.v) \
                  FROM units, q WHERE embedding IS NOT NULL AND q.v IS NOT NULL ORDER BY 3 LIMIT {TEXT_LEG}) \
               UNION ALL {fact_lexical} \
               UNION ALL (SELECT 'fact', fact_id, row_number() OVER (ORDER BY embedding <=> q.v) \
                  FROM facts, q WHERE embedding IS NOT NULL AND q.v IS NOT NULL ORDER BY 3 LIMIT {TEXT_LEG}) \
               UNION ALL {person_lexical} \
               UNION ALL {asset_lexical}), \
             fused AS (SELECT k, id, sum(1.0 / ({rrf_k} + r)) AS score FROM ranked GROUP BY k, id \
                  ORDER BY score DESC, id LIMIT $10) \
             SELECT (CASE k \
                 WHEN 'unit' THEN (SELECT {UNIT_JSON} FROM brain_unit u WHERE u.unit_id = fused.id) \
                 WHEN 'fact' THEN (SELECT {FACT_JSON} FROM brain_fact f JOIN brain_unit u USING (unit_id) WHERE f.fact_id = fused.id) \
                 WHEN 'person' THEN (SELECT {PERSON_JSON} FROM brain_person p WHERE p.slug = fused.id) \
                 ELSE (SELECT {ASSET_JSON} FROM brain_asset a WHERE a.path = fused.id) END \
               || jsonb_build_object('score', round(score, 5)))::text \
             FROM fused ORDER BY score DESC, id",
            prefix_dims = super::PREFIX_DIMS,
            rrf_k = super::RRF_K,
            who = person_slugs("$4"),
            unit_lexical = keyword_leg("unit", "brain_unit", "unit_id", "units", TEXT_LEG),
            fact_lexical = keyword_leg("fact", "brain_fact", "fact_id", "facts", TEXT_LEG),
            person_lexical = keyword_leg("person", "brain_person", "slug", "people", NAME_LEG),
            asset_lexical = keyword_leg("asset", "brain_asset", "path", "assets", NAME_LEG),
        );
        let withheld_sql = "SELECT $1 <> '' AND ( \
               EXISTS (SELECT 1 FROM brain_unit u WHERE ((u.local_only AND NOT $2) OR u.secret IS NOT NULL) \
                   AND u.doc ||| $1) \
            OR EXISTS (SELECT 1 FROM brain_fact f JOIN brain_unit u USING (unit_id) \
                   WHERE ((f.local_only AND NOT $2) OR u.secret IS NOT NULL) AND f.doc ||| $1) \
            OR EXISTS (SELECT 1 FROM brain_person p WHERE p.local_only AND NOT $2 AND p.doc ||| $1) \
            OR EXISTS (SELECT 1 FROM brain_asset a WHERE a.local_only AND NOT $2 AND a.doc ||| $1))";
        self.run(move |pool| async move {
            let rows: Vec<String> = sqlx::query_scalar(&sql)
                .bind(&terms)
                .bind(embedding)
                .bind(filters.kind)
                .bind(filters.person)
                .bind(filters.source)
                .bind(filters.topic)
                .bind(filters.from)
                .bind(filters.to)
                .bind(local)
                .bind(limit)
                .fetch_all(&pool)
                .await?;
            let withheld: bool = sqlx::query_scalar(withheld_sql)
                .bind(&terms)
                .bind(local)
                .fetch_one(&pool)
                .await?;
            Ok((rows, withheld))
        })
        .and_then(|(rows, withheld)| {
            Ok(RecordHits {
                hits: rows.into_iter().map(parse).collect::<BrainResult<_>>()?,
                withheld,
            })
        })
    }

    /// The brain pipeline's status (brain-status, loaded by brain-load) and
    /// when it was loaded.
    pub fn read_status(&self) -> BrainResult<RecordRead> {
        let doc: Option<String> = self.run(|pool| async move {
            sqlx::query_scalar(
                "SELECT (doc || jsonb_build_object('loaded', loaded))::text \
                 FROM brain_status WHERE scope = 'brain'",
            )
            .fetch_optional(&pool)
            .await
        })?;
        doc.map_or(Ok(RecordRead::Missing), |doc| {
            parse(doc).map(RecordRead::Found)
        })
    }

    /// Every name a turn may name: `(kind, key, name)` for each person's
    /// name and handles (local-only people left out), each project's id
    /// and name, and each Discord server's name.
    pub fn known_names(&self) -> BrainResult<Vec<(String, String, String)>> {
        self.run(|pool| async move {
            sqlx::query_as(
                "SELECT 'person', slug, name FROM brain_person WHERE NOT local_only \
                 UNION SELECT 'person', h.slug, h.value FROM brain_person_handle h \
                   JOIN brain_person p USING (slug) \
                   WHERE NOT p.local_only AND h.kind IN ('name', 'handle') \
                 UNION SELECT 'project', project_id, project_id FROM brain_project \
                 UNION SELECT 'project', project_id, name FROM brain_project \
                 UNION SELECT 'place', server_id, server FROM brain_channel \
                   WHERE server IS NOT NULL AND server_id IS NOT NULL",
            )
            .fetch_all(&pool)
            .await
        })
    }

    /// One person by slug or by an exact name, alias, handle, email, phone
    /// or photo-library person id, else by every word of a name ("ada"); a key
    /// several people share answers with the candidates. The person comes
    /// with their map: the conversation units they resolve to (latest
    /// first), the people, projects and Discord places those share, and the
    /// photos they are on.
    pub fn read_person(&self, key: &str, local: bool, limit: i64) -> BrainResult<RecordRead> {
        let key = key.trim().trim_start_matches('@').to_owned();
        if key.is_empty() {
            return Ok(RecordRead::Missing);
        }
        let matched = format!(
            "WITH exact AS ({who}) SELECT p.slug, p.name, p.local_only, p.source_path FROM brain_person p \
             WHERE p.slug IN (SELECT slug FROM exact) OR (NOT EXISTS (SELECT 1 FROM exact) \
               AND p.doc &&& $1) \
             ORDER BY p.slug LIMIT {MATCHES}",
            who = person_slugs("$1")
        );
        let rows =
            self.run(
                move |pool| async move { sqlx::query(&matched).bind(key).fetch_all(&pool).await },
            )?;
        let slug = match rows.as_slice() {
            [] => return Ok(RecordRead::Missing),
            [row] => {
                let (slug, local_only, path): (String, bool, String) =
                    (row.get(0), row.get(2), row.get(3));
                if local_only && !local {
                    return Ok(RecordRead::Withheld(local_only_reason(&slug, &path)));
                }
                slug
            }
            rows => {
                return Ok(RecordRead::Found(serde_json::json!({
                    "candidates": rows.iter().map(|row| serde_json::json!({
                        "id": if row.get::<bool, _>(2) && !local { None } else { Some(row.get::<String, _>(0)) },
                        "name": if row.get::<bool, _>(2) && !local { None } else { Some(row.get::<String, _>(1)) },
                    })).collect::<Vec<_>>(),
                    "note": "several people match; read one by its id",
                })))
            }
        };
        let sql = format!(
            "WITH s AS (SELECT u.* FROM brain_unit u WHERE u.persons @> ARRAY[$1] AND {SERVABLE}), \
                  ph AS (SELECT a.* FROM brain_asset a WHERE a.persons @> ARRAY[$1] AND a.kind = 'photo' \
                         AND (NOT a.local_only OR $2)) \
             SELECT ({PERSON_JSON} || {map} || jsonb_build_object('photos', jsonb_build_object( \
                 'count', (SELECT count(*) FROM ph), \
                 'recent', coalesce((SELECT jsonb_agg(x ORDER BY x->>'dated' DESC NULLS LAST) FROM \
                     (SELECT {ASSET_JSON} AS x FROM ph a ORDER BY a.dated DESC NULLS LAST, a.path LIMIT $3) r), '[]'))))::text \
             FROM brain_person p WHERE p.slug = $1",
            map = map_json("$1")
        );
        let found: String = self.run(move |pool| async move {
            sqlx::query_scalar(&sql)
                .bind(slug)
                .bind(local)
                .bind(limit)
                .fetch_one(&pool)
                .await
        })?;
        parse(found).map(RecordRead::Found)
    }

    /// One project (projects.toml id or name) with its map: its child
    /// projects, the topics tagged with it or a descendant, and the units
    /// under those topics with the people, projects and places they share.
    pub fn read_project(&self, key: &str, local: bool, limit: i64) -> BrainResult<RecordRead> {
        let key = key.trim().to_owned();
        let rows = self.run(move |pool| async move {
            sqlx::query(
                "SELECT project_id, name FROM brain_project \
                 WHERE project_id = lower($1) OR lower(name) = lower($1) ORDER BY project_id",
            )
            .bind(key)
            .fetch_all(&pool)
            .await
        })?;
        let id: String = match rows.as_slice() {
            [] => return Ok(RecordRead::Missing),
            [row] => row.get(0),
            rows => return Ok(candidates(rows)),
        };
        let sql = format!(
            "WITH RECURSIVE family AS (SELECT project_id FROM brain_project WHERE project_id = $1 \
                 UNION SELECT c.project_id FROM brain_project c JOIN family f ON c.parent = f.project_id), \
             t AS (SELECT tp.topic_id FROM brain_topic_project tp JOIN family USING (project_id)), \
             s AS (SELECT u.* FROM brain_unit u WHERE {SERVABLE} \
                   AND u.unit_id IN (SELECT tu.unit_id FROM brain_topic_unit tu JOIN t USING (topic_id))) \
             SELECT (jsonb_build_object('kind', 'project', 'id', b.project_id, 'name', b.name, \
                 'parent', b.parent, 'description', b.description, 'places', b.places, \
                 'children', (SELECT coalesce(jsonb_agg(c.project_id ORDER BY c.project_id), '[]') \
                              FROM brain_project c WHERE c.parent = b.project_id), \
                 'topicCount', (SELECT count(*) FROM t), \
                 'topics', coalesce((SELECT jsonb_agg(jsonb_build_object('id', x.topic_id, 'name', x.name, \
                         'units', x.unit_count) ORDER BY x.unit_count DESC, x.topic_id) \
                     FROM (SELECT o.* FROM brain_topic o JOIN t USING (topic_id) WHERE NOT o.local_only OR $2 \
                           ORDER BY o.unit_count DESC, o.topic_id LIMIT $3) x), '[]')) \
               || {map})::text \
             FROM brain_project b WHERE b.project_id = $1",
            map = map_json("NULL")
        );
        self.map_read(sql, id, local, limit)
    }

    /// A Discord server (name or id) or one channel or thread (id, name, or
    /// `server/channel`), with its map: how many units, the latest, and the
    /// people, projects and channels they share.
    pub fn read_place(&self, key: &str, local: bool, limit: i64) -> BrainResult<RecordRead> {
        let key = key.trim().to_owned();
        let rows = self.run(move |pool| async move {
            let servers = sqlx::query(
                "SELECT server_id, min(server), 'server' FROM brain_channel \
                 WHERE server_id = $1 OR lower(server) = lower($1) GROUP BY server_id ORDER BY 1",
            )
            .bind(&key)
            .fetch_all(&pool)
            .await?;
            if !servers.is_empty() {
                return Ok(servers);
            }
            sqlx::query(
                "SELECT channel_id, coalesce(server || '/', '') || name, 'channel' FROM brain_channel \
                 WHERE channel_id = $1 OR lower(name) = lower($1) OR lower(server || '/' || name) = lower($1) \
                 ORDER BY 1",
            )
            .bind(&key)
            .fetch_all(&pool)
            .await
        })?;
        let (id, server): (String, bool) = match rows.as_slice() {
            [] => return Ok(RecordRead::Missing),
            [row] => (row.get(0), row.get::<String, _>(2) == "server"),
            rows => return Ok(candidates(rows)),
        };
        let (place, head, from) = if server {
            (
                "SELECT channel_id FROM brain_channel WHERE server_id = $1",
                "jsonb_build_object('kind', 'server', 'id', c.server_id, 'name', c.server, 'channels', c.n)",
                "(SELECT server_id, min(server) AS server, count(*) AS n FROM brain_channel \
                  WHERE server_id = $1 GROUP BY server_id) c",
            )
        } else {
            (
                "SELECT $1",
                "jsonb_build_object('kind', 'channel', 'id', c.channel_id, 'name', c.name, \
                 'channelKind', c.kind, 'server', c.server, 'serverId', c.server_id, \
                 'parent', c.parent, 'parentId', c.parent_id)",
                "brain_channel c WHERE c.channel_id = $1",
            )
        };
        let sql = format!(
            "WITH s AS (SELECT u.* FROM brain_unit u WHERE {SERVABLE} AND u.channel_id IN ({place})) \
             SELECT ({head} || {map})::text FROM {from}",
            map = map_json("NULL")
        );
        self.map_read(sql, id, local, limit)
    }

    /// Runs one map query over `$1` (the resolved id), `$2` (local lane)
    /// and `$3` (list length).
    fn map_read(
        &self,
        sql: String,
        id: String,
        local: bool,
        limit: i64,
    ) -> BrainResult<RecordRead> {
        let found: Option<String> = self.run(move |pool| async move {
            sqlx::query_scalar(&sql)
                .bind(id)
                .bind(local)
                .bind(limit)
                .fetch_optional(&pool)
                .await
        })?;
        found.map_or(Ok(RecordRead::Missing), |text| {
            parse(text).map(RecordRead::Found)
        })
    }

    /// One fact with its evidence lines and its unit's summary.
    pub fn read_fact(&self, id: &str, local: bool) -> BrainResult<RecordRead> {
        let id = id.to_owned();
        let sql = format!(
            "SELECT f.local_only, u.secret, u.source_path, \
                    ({FACT_JSON} || jsonb_build_object('unitSummary', u.summary))::text \
             FROM brain_fact f JOIN brain_unit u USING (unit_id) WHERE f.fact_id = $1"
        );
        let row = self.run({
            let id = id.clone();
            move |pool| async move { sqlx::query(&sql).bind(id).fetch_optional(&pool).await }
        })?;
        let Some(row) = row else {
            return Ok(RecordRead::Missing);
        };
        let (local_only, secret, path): (bool, Option<String>, String) =
            (row.get(0), row.get(1), row.get(2));
        if let Some(rule) = secret {
            return Ok(RecordRead::Withheld(secret_reason(&id, &rule)));
        }
        if local_only && !local {
            return Ok(RecordRead::Withheld(local_only_reason(&id, &path)));
        }
        parse(row.get(3)).map(RecordRead::Found)
    }

    /// Photos and documents by name words, date range, the person on them
    /// and, for photos, a place given as `(lat, lon, km)`.
    pub fn find_assets(
        &self,
        query: &str,
        filters: &RecordFilters,
        near: Option<(f64, f64, f64)>,
        local: bool,
        limit: i64,
    ) -> BrainResult<RecordHits> {
        let terms = keyword_text(query);
        let (kind, from, to, person) = (
            filters.kind.clone(),
            filters.from.clone(),
            filters.to.clone(),
            filters.person.clone(),
        );
        let (lat, lon, km) =
            near.map_or((None, None, None), |(a, b, c)| (Some(a), Some(b), Some(c)));
        // With words, the best BM25 matches first; without, the newest.
        let (matched, order) = if terms.is_empty() {
            ("$1 = ''", "a.dated DESC NULLS LAST, a.path")
        } else {
            ("a.doc ||| $1", "pdb.score(a.path) DESC, a.path")
        };
        let sql = format!(
            "SELECT a.local_only, ({ASSET_JSON})::text FROM brain_asset a \
             WHERE {matched} AND ($2::text IS NULL OR a.kind = $2) \
               AND ($3::date IS NULL OR a.dated >= $3::date) AND ($4::date IS NULL OR a.dated < $4::date + 1) \
               AND ($5::float8 IS NULL OR ((a.place->>'lat')::float8 BETWEEN $5 - $7 / 111.0 AND $5 + $7 / 111.0 \
                 AND (a.place->>'lon')::float8 BETWEEN $6 - $7 / (111.0 * greatest(cos(radians($5)), 0.01)) \
                                                    AND $6 + $7 / (111.0 * greatest(cos(radians($5)), 0.01)))) \
               AND ($9::text IS NULL OR a.persons && ARRAY({who})) \
             ORDER BY {order} LIMIT $8",
            who = person_slugs("$9"),
        );
        let rows = self.run(move |pool| async move {
            sqlx::query(&sql)
                .bind(terms)
                .bind(kind)
                .bind(from)
                .bind(to)
                .bind(lat)
                .bind(lon)
                .bind(km)
                .bind(limit)
                .bind(person)
                .fetch_all(&pool)
                .await
        })?;
        let mut hits = RecordHits {
            hits: Vec::new(),
            withheld: false,
        };
        for row in rows {
            if row.get::<bool, _>(0) && !local {
                hits.withheld = true;
            } else {
                hits.hits.push(parse(row.get(1))?);
            }
        }
        Ok(hits)
    }

    /// One asset by its exact path, gated like every read.
    pub fn read_asset(&self, path: &str, local: bool) -> BrainResult<RecordRead> {
        let path = path.to_owned();
        let sql = format!(
            "SELECT a.local_only, ({ASSET_JSON})::text FROM brain_asset a WHERE a.path = $1"
        );
        let row = self.run({
            let path = path.clone();
            move |pool| async move { sqlx::query(&sql).bind(path).fetch_optional(&pool).await }
        })?;
        match row {
            None => Ok(RecordRead::Missing),
            Some(row) if row.get::<bool, _>(0) && !local => Ok(RecordRead::Withheld(
                local_only_reason(&path, &format!("raw/{path}")),
            )),
            Some(row) => parse(row.get(1)).map(RecordRead::Found),
        }
    }
}
