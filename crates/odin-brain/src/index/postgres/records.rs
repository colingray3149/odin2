//! Curated brain records (migration 0005, written by the brain repo's
//! `scripts/brain-load`): people and their handles, curated conversation
//! units, facts with their evidence lines, and the photo/doc index.
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

/// The `idf` CTE of one table: each query term's inverse document
/// frequency over the whole table, so a rare word ("japan") outweighs a
/// common one ("talk") in the lexical rank.
fn term_weights(name: &str, table: &str, config: &str) -> String {
    format!(
        "{name} AS (SELECT to_tsquery('{config}', t) AS tq, \
             ln(((SELECT count(*) FROM {table}) + 1)::float8 \
                / (1 + (SELECT count(*) FROM {table} d WHERE d.tsv @@ to_tsquery('{config}', t)))) AS idf \
             FROM q, unnest(q.terms) t)"
    )
}

/// One lexical leg: rows matching any term, ranked by the summed squared
/// weight of the distinct terms they match (one rare word outweighs several
/// common ones), then by `ts_rank`.
fn lexical_leg(kind: &str, id: &str, rows: &str, weights: &str, query: &str, limit: u32) -> String {
    format!(
        "(SELECT '{kind}' AS k, {id} AS id, row_number() OVER ( \
             ORDER BY (SELECT coalesce(sum(w.idf * w.idf), 0) FROM {weights} w WHERE x.tsv @@ w.tq) DESC, \
                      ts_rank(x.tsv, q.{query}) DESC) AS r \
           FROM {rows} x, q WHERE x.tsv @@ q.{query} ORDER BY 3 LIMIT {limit})"
    )
}

impl BrainPostgres {
    /// Hybrid search over units, facts, people and assets: lexical
    /// (any query term) and, given a query embedding, 256-d cosine
    /// candidates, fused by reciprocal rank.
    pub fn search_records(
        &self,
        query: &str,
        embedding: Option<Vec<f32>>,
        filters: &RecordFilters,
        local: bool,
        limit: i64,
    ) -> BrainResult<RecordHits> {
        let terms = super::tsquery_terms(crate::retrieval::rank::terms(query).collect());
        let embedding = embedding.map(|mut dims| {
            dims.truncate(super::PREFIX_DIMS);
            dims
        });
        let filters = filters.clone();
        let sql = format!(
            "WITH q AS (SELECT CASE WHEN $1 = '' THEN NULL ELSE to_tsquery('english', $1) END AS en, \
                               CASE WHEN $1 = '' THEN NULL ELSE to_tsquery('simple', $1) END AS si, \
                               CASE WHEN $1 = '' THEN '{{}}'::text[] ELSE string_to_array($1, ' | ') END AS terms, \
                               $2::real[]::halfvec(256) AS v), \
             {unit_weights}, {fact_weights}, {person_weights}, {asset_weights}, \
             units AS (SELECT u.* FROM brain_unit u WHERE (NOT u.local_only OR $9) AND u.secret IS NULL \
                 AND ($3::text IS NULL OR $3 = 'unit') AND ($5::text IS NULL OR u.source = $5) \
                 AND ($6::text IS NULL OR $6 = ANY (u.topics)) AND ($4::text IS NULL OR u.people::text ILIKE '%' || $4 || '%') \
                 AND ($7::date IS NULL OR u.last_ts >= $7::date) AND ($8::date IS NULL OR u.first_ts < $8::date + 1)), \
             facts AS (SELECT f.* FROM brain_fact f JOIN brain_unit u USING (unit_id) \
                 WHERE (NOT f.local_only OR $9) AND u.secret IS NULL \
                 AND ($3::text IS NULL OR $3 = 'fact') AND ($5::text IS NULL OR u.source = $5) \
                 AND ($6::text IS NULL OR $6 = ANY (u.topics)) \
                 AND ($4::text IS NULL OR f.subject ILIKE '%' || $4 || '%' OR u.people::text ILIKE '%' || $4 || '%') \
                 AND ($7::date IS NULL OR coalesce(f.valid_from, u.last_ts) >= $7::date) \
                 AND ($8::date IS NULL OR coalesce(f.valid_from, u.first_ts) < $8::date + 1)), \
             people AS (SELECT p.* FROM brain_person p WHERE (NOT p.local_only OR $9) \
                 AND ($3::text IS NULL OR $3 = 'person') AND $5::text IS NULL AND $6::text IS NULL \
                 AND ($4::text IS NULL OR p.tsv @@ plainto_tsquery('simple', $4))), \
             assets AS (SELECT a.* FROM brain_asset a WHERE (NOT a.local_only OR $9) \
                 AND ($3::text IS NULL OR $3 = a.kind) AND $4::text IS NULL AND $5::text IS NULL AND $6::text IS NULL \
                 AND ($7::date IS NULL OR a.dated >= $7::date) AND ($8::date IS NULL OR a.dated < $8::date + 1)), \
             ranked AS ( \
               {unit_lexical} \
               UNION ALL (SELECT 'unit', unit_id, row_number() OVER (ORDER BY embedding <=> q.v) \
                  FROM units, q WHERE embedding IS NOT NULL AND q.v IS NOT NULL ORDER BY 3 LIMIT 40) \
               UNION ALL {fact_lexical} \
               UNION ALL (SELECT 'fact', fact_id, row_number() OVER (ORDER BY embedding <=> q.v) \
                  FROM facts, q WHERE embedding IS NOT NULL AND q.v IS NOT NULL ORDER BY 3 LIMIT 40) \
               UNION ALL {person_lexical} \
               UNION ALL {asset_lexical}), \
             fused AS (SELECT k, id, sum(1.0 / (60 + r)) AS score FROM ranked GROUP BY k, id \
                  ORDER BY score DESC, id LIMIT $10) \
             SELECT (CASE k \
                 WHEN 'unit' THEN (SELECT {UNIT_JSON} FROM brain_unit u WHERE u.unit_id = fused.id) \
                 WHEN 'fact' THEN (SELECT {FACT_JSON} FROM brain_fact f JOIN brain_unit u USING (unit_id) WHERE f.fact_id = fused.id) \
                 WHEN 'person' THEN (SELECT {PERSON_JSON} FROM brain_person p WHERE p.slug = fused.id) \
                 ELSE (SELECT {ASSET_JSON} FROM brain_asset a WHERE a.path = fused.id) END \
               || jsonb_build_object('score', round(score, 5)))::text \
             FROM fused ORDER BY score DESC, id",
            unit_weights = term_weights("unit_idf", "brain_unit", "english"),
            fact_weights = term_weights("fact_idf", "brain_fact", "english"),
            person_weights = term_weights("person_idf", "brain_person", "simple"),
            asset_weights = term_weights("asset_idf", "brain_asset", "simple"),
            unit_lexical = lexical_leg("unit", "unit_id", "units", "unit_idf", "en", 40),
            fact_lexical = lexical_leg("fact", "fact_id", "facts", "fact_idf", "en", 40),
            person_lexical = lexical_leg("person", "slug", "people", "person_idf", "si", 20),
            asset_lexical = lexical_leg("asset", "path", "assets", "asset_idf", "si", 20),
        );
        let withheld_sql = "SELECT $1 <> '' AND ( \
               EXISTS (SELECT 1 FROM brain_unit u WHERE ((u.local_only AND NOT $2) OR u.secret IS NOT NULL) \
                   AND u.tsv @@ to_tsquery('english', $1)) \
            OR EXISTS (SELECT 1 FROM brain_fact f JOIN brain_unit u USING (unit_id) \
                   WHERE ((f.local_only AND NOT $2) OR u.secret IS NOT NULL) AND f.tsv @@ to_tsquery('english', $1)) \
            OR EXISTS (SELECT 1 FROM brain_person p WHERE p.local_only AND NOT $2 AND p.tsv @@ to_tsquery('simple', $1)) \
            OR EXISTS (SELECT 1 FROM brain_asset a WHERE a.local_only AND NOT $2 AND a.tsv @@ to_tsquery('simple', $1)))";
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

    /// One person by slug or by an exact name, handle, email or phone; a
    /// key several people share answers with the candidates. Includes the
    /// most recent servable conversation units that name them.
    pub fn read_person(&self, key: &str, local: bool) -> BrainResult<RecordRead> {
        let key = key.trim().trim_start_matches('@').to_owned();
        let sql = format!(
            "WITH m AS (SELECT slug FROM brain_person WHERE slug = $1 \
                        UNION SELECT slug FROM brain_person_handle WHERE lower(value) = lower($1)) \
             SELECT p.slug, p.name, p.local_only, p.source_path, ({PERSON_JSON} || jsonb_build_object('units', \
               coalesce((SELECT jsonb_agg(x ORDER BY x->>'to' DESC NULLS LAST) FROM ( \
                 SELECT {UNIT_JSON} AS x FROM brain_unit u WHERE (NOT u.local_only OR $2) AND u.secret IS NULL \
                   AND EXISTS (SELECT 1 FROM jsonb_array_elements(u.people) e, brain_person_handle h \
                     WHERE h.slug = p.slug AND h.kind IN ('name', 'handle') \
                       AND lower(h.value) IN (lower(e->>'name'), lower(e->>'handle'))) \
                   ORDER BY u.last_ts DESC NULLS LAST LIMIT 5) s), '[]')))::text \
             FROM brain_person p JOIN m USING (slug) ORDER BY p.slug"
        );
        let rows = self.run(move |pool| async move {
            sqlx::query(&sql)
                .bind(key)
                .bind(local)
                .fetch_all(&pool)
                .await
        })?;
        match rows.as_slice() {
            [] => Ok(RecordRead::Missing),
            [row] => {
                let (slug, local_only, path): (String, bool, String) =
                    (row.get(0), row.get(2), row.get(3));
                if local_only && !local {
                    return Ok(RecordRead::Withheld(local_only_reason(&slug, &path)));
                }
                parse(row.get(4)).map(RecordRead::Found)
            }
            rows => Ok(RecordRead::Found(serde_json::json!({
                "candidates": rows.iter().map(|row| serde_json::json!({
                    "id": row.get::<String, _>(0),
                    "name": if row.get::<bool, _>(2) && !local { None } else { Some(row.get::<String, _>(1)) },
                })).collect::<Vec<_>>(),
                "note": "several people match; read one by its id",
            }))),
        }
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

    /// Photos and documents by name words, date range and, for photos,
    /// a place given as `(lat, lon, km)`.
    pub fn find_assets(
        &self,
        query: &str,
        filters: &RecordFilters,
        near: Option<(f64, f64, f64)>,
        local: bool,
        limit: i64,
    ) -> BrainResult<RecordHits> {
        let terms = super::tsquery_terms(crate::retrieval::rank::terms(query).collect());
        let (kind, from, to) = (
            filters.kind.clone(),
            filters.from.clone(),
            filters.to.clone(),
        );
        let (lat, lon, km) =
            near.map_or((None, None, None), |(a, b, c)| (Some(a), Some(b), Some(c)));
        let sql = format!(
            "SELECT a.local_only, ({ASSET_JSON})::text FROM brain_asset a \
             WHERE ($1 = '' OR a.tsv @@ to_tsquery('simple', $1)) AND ($2::text IS NULL OR a.kind = $2) \
               AND ($3::date IS NULL OR a.dated >= $3::date) AND ($4::date IS NULL OR a.dated < $4::date + 1) \
               AND ($5::float8 IS NULL OR ((a.place->>'lat')::float8 BETWEEN $5 - $7 / 111.0 AND $5 + $7 / 111.0 \
                 AND (a.place->>'lon')::float8 BETWEEN $6 - $7 / (111.0 * greatest(cos(radians($5)), 0.01)) \
                                                    AND $6 + $7 / (111.0 * greatest(cos(radians($5)), 0.01)))) \
             ORDER BY a.dated DESC NULLS LAST, a.path LIMIT $8"
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
