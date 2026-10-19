//! Bounded SQLite provenance reads sharing one row parser.

use odin_domain::knowledge::ids::{IndexGenerationId, KnowledgeItemId};
use rusqlite::{params, Connection, OptionalExtension};

use super::{corrupt, parse_source_class};
use crate::error::BrainResult;
use crate::index::model::ItemProvenance;

/// Upper bound on one provenance batch, the seal copy's batch size.
pub(crate) const PROVENANCE_BATCH: usize = 500;

/// Parses one stored provenance row, typed-invalid as corruption.
pub(crate) fn parse_provenance_row(
    item_id: String,
    node_id: String,
    path: String,
    source_class: String,
    scope_tags: String,
) -> BrainResult<(KnowledgeItemId, ItemProvenance)> {
    let item_id = KnowledgeItemId::parse(&item_id)
        .map_err(|_| corrupt("provenance item id is not a canonical digest"))?;
    let source_class = parse_source_class(&source_class)
        .ok_or_else(|| corrupt("provenance source class is not a known class"))?;
    let scope_tags = if scope_tags.is_empty() {
        Vec::new()
    } else {
        scope_tags.split('\0').map(str::to_owned).collect()
    };
    Ok((
        item_id,
        ItemProvenance {
            node_id,
            path,
            source_class,
            scope_tags,
        },
    ))
}

/// Reads at most [`PROVENANCE_BATCH`] provenance rows of one generation in
/// canonical item order, strictly after `after_item` (`None` starts the
/// generation; the previous batch's last item id continues it). An empty
/// batch ends the generation.
pub(crate) fn read_provenance_batch(
    connection: &Connection,
    generation_id: &IndexGenerationId,
    after_item: Option<&str>,
    limit: usize,
) -> BrainResult<Vec<(KnowledgeItemId, ItemProvenance)>> {
    let mut statement = connection.prepare_cached(
        "SELECT item_id, node_id, path, source_class, scope_tags
         FROM brain_index_item_provenance
         WHERE generation_id = ?1 AND (?2 IS NULL OR item_id > ?2)
         ORDER BY item_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            generation_id.to_string(),
            after_item,
            limit.min(PROVENANCE_BATCH) as i64
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )?;
    rows.map(|row| {
        let (item_id, node_id, path, source_class, scope_tags) = row?;
        parse_provenance_row(item_id, node_id, path, source_class, scope_tags)
    })
    .collect::<BrainResult<Vec<_>>>()
}

/// Reads one item's stored provenance; `Ok(None)` when it has none.
pub(crate) fn read_one_provenance(
    connection: &Connection,
    generation_id: &IndexGenerationId,
    item_id: &KnowledgeItemId,
) -> BrainResult<Option<ItemProvenance>> {
    connection
        .query_row(
            "SELECT item_id, node_id, path, source_class, scope_tags
             FROM brain_index_item_provenance
             WHERE generation_id = ?1 AND item_id = ?2",
            params![generation_id.to_string(), item_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .map(|(item_id, node_id, path, source_class, scope_tags)| {
            parse_provenance_row(item_id, node_id, path, source_class, scope_tags)
                .map(|(_, item_provenance)| item_provenance)
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU32;

    use odin_atlas::SourceClass;
    use odin_domain::knowledge::ids::AtlasId;
    use odin_domain::knowledge::retrieval::TrustClass;
    use odin_domain::Digest;
    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::error::BrainError;
    use crate::index::build::{build_index, Chunker};
    use crate::index::store::{read_item_provenance, IndexStore};
    use crate::source::SourceItem;

    fn provenance_item(source: &AtlasId, revision: Digest, key: &str) -> SourceItem {
        SourceItem::new(
            source.clone(),
            revision,
            key.as_bytes(),
            TrustClass::Curated,
            format!("text {key} alpha beta gamma delta"),
        )
        .unwrap()
        .with_provenance(ItemProvenance {
            node_id: format!("crate:prov:node-{key}"),
            path: format!("crates/prov/src/{key}.rs"),
            source_class: SourceClass::Rust,
            scope_tags: vec!["scope:prov".to_owned(), "scope:extra".to_owned()],
        })
    }

    /// Streams one small provenance-bearing generation into a fresh store.
    fn opened() -> (TempDir, IndexStore, IndexGenerationId) {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path()).unwrap();
        let source = AtlasId::new("atlas:prov").unwrap();
        let revision = Digest::hash(b"reader");
        let items = vec![provenance_item(&source, revision, "seed")];
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index(source, revision, &items, &chunker).unwrap();
        store.store(&build, 7).unwrap();
        (dir, store, build.generation.generation_id)
    }

    /// Adds `count` valid bulk provenance rows directly, so volume tests do
    /// not need a proportional build.
    fn bulk_rows(store: &IndexStore, id: &IndexGenerationId, count: usize) {
        let connection = store.lock_connection().unwrap();
        let mut insert = connection
            .prepare(
                "INSERT INTO brain_index_item_provenance
                    (generation_id, item_id, node_id, path, source_class, scope_tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .unwrap();
        for index in 0..count {
            let item_id = KnowledgeItemId::new(Digest::hash(format!("bulk-{index}").as_bytes()));
            insert
                .execute(params![
                    id.to_string(),
                    item_id.to_string(),
                    format!("crate:prov:bulk-{index}"),
                    format!("crates/prov/src/bulk_{index}.rs"),
                    "rust",
                    "scope:bulk\0scope:extra",
                ])
                .unwrap();
        }
    }

    #[test]
    fn batches_cover_the_generation_in_canonical_order_without_overlap() {
        let (_dir, store, id) = opened();
        bulk_rows(&store, &id, 1_201);

        let connection = store.lock_connection().unwrap();
        let mut batches = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let batch =
                read_provenance_batch(&connection, &id, cursor.as_deref(), PROVENANCE_BATCH)
                    .unwrap();
            if batch.is_empty() {
                break;
            }
            cursor = Some(batch.last().unwrap().0.to_string());
            batches.push(batch);
        }

        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            [PROVENANCE_BATCH, PROVENANCE_BATCH, 202],
            "the bound holds per batch and the cursor exhausts the generation"
        );
        let whole = read_item_provenance(&connection, &id).unwrap();
        let flat: Vec<(KnowledgeItemId, ItemProvenance)> = batches.into_iter().flatten().collect();
        assert_eq!(flat.len(), 1_202, "no row is repeated or skipped");
        assert!(
            flat.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "batches arrive in canonical item order"
        );
        let flattened: BTreeMap<KnowledgeItemId, ItemProvenance> = flat.into_iter().collect();
        assert_eq!(flattened, whole, "batched reads match the whole-map read");
        let after_end =
            read_provenance_batch(&connection, &id, cursor.as_deref(), PROVENANCE_BATCH).unwrap();
        assert!(after_end.is_empty(), "an exhausted cursor stays exhausted");
    }

    #[test]
    fn an_empty_generation_reads_as_one_empty_batch() {
        let (_dir, store, id) = opened();
        let connection = store.lock_connection().unwrap();
        connection
            .execute(
                "DELETE FROM brain_index_item_provenance WHERE generation_id = ?1",
                params![id.to_string()],
            )
            .unwrap();
        let batch = read_provenance_batch(&connection, &id, None, PROVENANCE_BATCH).unwrap();
        assert!(batch.is_empty());
    }

    #[test]
    fn a_non_canonical_item_id_is_typed_corruption() {
        let (_dir, store, id) = opened();
        {
            let connection = store.lock_connection().unwrap();
            connection
                .execute(
                    "INSERT INTO brain_index_item_provenance
                        (generation_id, item_id, node_id, path, source_class, scope_tags)
                     VALUES (?1, '-not-a-digest', 'node', 'path', 'rust', '')",
                    params![id.to_string()],
                )
                .unwrap();
        }
        let connection = store.lock_connection().unwrap();
        let error = read_provenance_batch(&connection, &id, None, PROVENANCE_BATCH).unwrap_err();
        assert!(matches!(error, BrainError::Corrupt { .. }), "{error:?}");
    }

    #[test]
    fn an_unknown_source_class_is_typed_corruption() {
        let (_dir, store, id) = opened();
        {
            let connection = store.lock_connection().unwrap();
            let item_id = KnowledgeItemId::new(Digest::hash(b"bogus-class"));
            connection
                .execute(
                    "INSERT INTO brain_index_item_provenance
                        (generation_id, item_id, node_id, path, source_class, scope_tags)
                     VALUES (?1, ?2, 'node', 'path', 'bogus', '')",
                    params![id.to_string(), item_id.to_string()],
                )
                .unwrap();
        }
        let connection = store.lock_connection().unwrap();
        let error = read_provenance_batch(&connection, &id, None, PROVENANCE_BATCH).unwrap_err();
        assert!(matches!(error, BrainError::Corrupt { .. }), "{error:?}");
    }

    #[test]
    fn one_item_reads_its_row_or_none_without_the_rest() {
        let (_dir, store, id) = opened();
        bulk_rows(&store, &id, 40);
        let connection = store.lock_connection().unwrap();

        let item_id = KnowledgeItemId::new(Digest::hash(b"bulk-7"));
        let item_provenance = read_one_provenance(&connection, &id, &item_id)
            .unwrap()
            .expect("the bulk row exists");
        assert_eq!(item_provenance.node_id, "crate:prov:bulk-7");
        assert_eq!(item_provenance.path, "crates/prov/src/bulk_7.rs");
        assert_eq!(item_provenance.scope_tags, ["scope:bulk", "scope:extra"]);

        let absent = KnowledgeItemId::new(Digest::hash(b"absent"));
        assert!(read_one_provenance(&connection, &id, &absent)
            .unwrap()
            .is_none());
    }
}
