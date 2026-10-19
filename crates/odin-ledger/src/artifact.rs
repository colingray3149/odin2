//! Content-addressed artifact metadata. Artifact bytes live outside SQLite.

use std::str::FromStr;

use odin_domain::{ArtifactId, Digest};
use rusqlite::{params, OptionalExtension, Row, Transaction};
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionClass {
    Canonical,
    Pinned,
    Regenerable,
    Scratch,
}

impl RetentionClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Pinned => "pinned",
            Self::Regenerable => "regenerable",
            Self::Scratch => "scratch",
        }
    }

    fn parse(value: &str) -> LedgerResult<Self> {
        match value {
            "canonical" => Ok(Self::Canonical),
            "pinned" => Ok(Self::Pinned),
            "regenerable" => Ok(Self::Regenerable),
            "scratch" => Ok(Self::Scratch),
            other => Err(LedgerError::invalid_data(format!(
                "artifact has unknown retention class {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactRegistration<'a> {
    pub bytes: &'a [u8],
    pub media_type: &'a str,
    pub storage_path: &'a str,
    pub retention: RetentionClass,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMetadata {
    pub artifact_id: ArtifactId,
    pub digest: Digest,
    pub size_bytes: u64,
    pub media_type: String,
    pub storage_path: String,
    pub retention: RetentionClass,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub verified_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct NewArtifactReference<'a> {
    pub object_kind: &'a str,
    pub object_id: &'a str,
    pub relation: &'a str,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactReference {
    pub artifact_id: ArtifactId,
    pub object_kind: String,
    pub object_id: String,
    pub relation: String,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachReference {
    Added(ArtifactMetadata),
    Existing(ArtifactMetadata),
}

impl Ledger {
    /// Records metadata derived from `bytes`; the bytes themselves are never written to SQLite.
    ///
    /// A digest already present in the ledger wins as a whole metadata record. This makes retries
    /// idempotent even when the retry supplies a different path or retention hint.
    pub fn register_artifact(
        &self,
        registration: ArtifactRegistration<'_>,
    ) -> LedgerResult<ArtifactMetadata> {
        let digest = Digest::hash(registration.bytes);
        let artifact_id = ArtifactId::from_str(&digest.to_string()).map_err(|error| {
            LedgerError::invalid_data_caused_by("generated artifact identifier is invalid", error)
        })?;
        let size_bytes = i64::try_from(registration.bytes.len()).map_err(|error| {
            LedgerError::invalid_data_caused_by("artifact size exceeds SQLite INTEGER", error)
        })?;

        self.connection().execute(
            "INSERT INTO artifacts (
                 artifact_ref, content_digest, size_bytes, media_type, storage_path,
                 retention_class, revision, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
             ON CONFLICT(content_digest) DO NOTHING",
            params![
                artifact_id.to_string(),
                digest.to_string(),
                size_bytes,
                registration.media_type,
                registration.storage_path,
                registration.retention.as_str(),
                encode_utc(registration.created_at)?,
            ],
        )?;

        self.artifact_by_digest(&digest)?.ok_or_else(|| {
            LedgerError::invalid_data(
                "artifact insert completed without a readable metadata row".to_owned(),
            )
        })
    }

    pub fn artifact(&self, artifact_id: &ArtifactId) -> LedgerResult<Option<ArtifactMetadata>> {
        let row = self
            .connection()
            .query_row(
                "SELECT artifact_ref, content_digest, size_bytes, media_type, storage_path,
                        retention_class, revision, created_at, verified_at
                 FROM artifacts
                 WHERE artifact_ref = ?1",
                [artifact_id.to_string()],
                artifact_row,
            )
            .optional()?;
        row.map(decode_artifact).transpose()
    }

    pub fn artifact_by_digest(&self, digest: &Digest) -> LedgerResult<Option<ArtifactMetadata>> {
        let row = self
            .connection()
            .query_row(
                "SELECT artifact_ref, content_digest, size_bytes, media_type, storage_path,
                        retention_class, revision, created_at, verified_at
                 FROM artifacts
                 WHERE content_digest = ?1",
                [digest.to_string()],
                artifact_row,
            )
            .optional()?;
        row.map(decode_artifact).transpose()
    }

    pub fn verify_artifact(
        &self,
        artifact_id: &ArtifactId,
        expected_revision: i64,
        verified_at: OffsetDateTime,
    ) -> LedgerResult<ArtifactMetadata> {
        let changed = self.connection().execute(
            "UPDATE artifacts
             SET verified_at = ?1, revision = revision + 1
             WHERE artifact_ref = ?2 AND revision = ?3",
            params![
                encode_utc(verified_at)?,
                artifact_id.to_string(),
                expected_revision
            ],
        )?;
        if changed == 0 {
            return Err(stale_artifact(self, artifact_id, expected_revision)?);
        }
        self.artifact(artifact_id)?.ok_or_else(|| {
            LedgerError::invalid_data(format!("verified artifact {artifact_id} disappeared"))
        })
    }

    pub fn attach_artifact_reference(
        &mut self,
        artifact_id: &ArtifactId,
        expected_revision: i64,
        reference: NewArtifactReference<'_>,
    ) -> LedgerResult<AttachReference> {
        let artifact_id = artifact_id.clone();
        self.with_tx(|transaction| {
            attach_reference(transaction, &artifact_id, expected_revision, reference)
        })
    }

    pub fn artifact_references(
        &self,
        artifact_id: &ArtifactId,
    ) -> LedgerResult<Vec<ArtifactReference>> {
        let mut statement = self.connection().prepare(
            "SELECT artifact_ref, object_kind, object_id, relation, created_at
             FROM artifact_refs
             WHERE artifact_ref = ?1
             ORDER BY object_kind, object_id, relation",
        )?;
        let rows = statement.query_map([artifact_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;

        rows.map(|row| {
            let (artifact, object_kind, object_id, relation, created_at) = row?;
            Ok(ArtifactReference {
                artifact_id: parse_artifact_id(&artifact)?,
                object_kind,
                object_id,
                relation,
                created_at: decode_utc(&created_at)?,
            })
        })
        .collect()
    }
}

fn attach_reference(
    transaction: &Transaction<'_>,
    artifact_id: &ArtifactId,
    expected_revision: i64,
    reference: NewArtifactReference<'_>,
) -> LedgerResult<AttachReference> {
    let current_revision = transaction
        .query_row(
            "SELECT revision FROM artifacts WHERE artifact_ref = ?1",
            [artifact_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::invalid_data(format!("unknown artifact {artifact_id}")))?;
    if current_revision != expected_revision {
        return Err(LedgerError::StaleActor {
            actor: format!("artifact:{artifact_id}"),
            expected_revision,
            actual_revision: current_revision,
        });
    }

    let added = transaction.execute(
        "INSERT INTO artifact_refs (
             artifact_ref, object_kind, object_id, relation, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(artifact_ref, object_kind, object_id, relation) DO NOTHING",
        params![
            artifact_id.to_string(),
            reference.object_kind,
            reference.object_id,
            reference.relation,
            encode_utc(reference.created_at)?,
        ],
    )?;
    if added != 0 {
        transaction.execute(
            "UPDATE artifacts SET revision = revision + 1
             WHERE artifact_ref = ?1 AND revision = ?2",
            params![artifact_id.to_string(), expected_revision],
        )?;
    }

    let metadata = transaction.query_row(
        "SELECT artifact_ref, content_digest, size_bytes, media_type, storage_path,
                retention_class, revision, created_at, verified_at
         FROM artifacts
         WHERE artifact_ref = ?1",
        [artifact_id.to_string()],
        artifact_row,
    )?;
    let metadata = decode_artifact(metadata)?;
    Ok(if added == 0 {
        AttachReference::Existing(metadata)
    } else {
        AttachReference::Added(metadata)
    })
}

type ArtifactRow = (
    String,
    String,
    i64,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
);

fn artifact_row(row: &Row<'_>) -> rusqlite::Result<ArtifactRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn decode_artifact(row: ArtifactRow) -> LedgerResult<ArtifactMetadata> {
    let (
        artifact_id,
        digest,
        size_bytes,
        media_type,
        storage_path,
        retention,
        revision,
        created_at,
        verified_at,
    ) = row;
    Ok(ArtifactMetadata {
        artifact_id: parse_artifact_id(&artifact_id)?,
        digest: Digest::from_str(&digest).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid artifact digest", error)
        })?,
        size_bytes: u64::try_from(size_bytes).map_err(|error| {
            LedgerError::invalid_data_caused_by(
                format!("artifact {artifact_id} has negative size {size_bytes}"),
                error,
            )
        })?,
        media_type,
        storage_path,
        retention: RetentionClass::parse(&retention)?,
        revision,
        created_at: decode_utc(&created_at)?,
        verified_at: verified_at.as_deref().map(decode_utc).transpose()?,
    })
}

fn parse_artifact_id(value: &str) -> LedgerResult<ArtifactId> {
    ArtifactId::from_str(value).map_err(|error| {
        LedgerError::invalid_data_caused_by(format!("invalid artifact identifier {value:?}"), error)
    })
}

fn stale_artifact(
    ledger: &Ledger,
    artifact_id: &ArtifactId,
    expected_revision: i64,
) -> LedgerResult<LedgerError> {
    let actual_revision = ledger
        .connection()
        .query_row(
            "SELECT revision FROM artifacts WHERE artifact_ref = ?1",
            [artifact_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::invalid_data(format!("unknown artifact {artifact_id}")))?;
    Ok(LedgerError::StaleActor {
        actor: format!("artifact:{artifact_id}"),
        expected_revision,
        actual_revision,
    })
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{ArtifactRegistration, RetentionClass};
    use crate::Ledger;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    #[test]
    fn digest_dedup_reuses_the_first_metadata_without_storing_bytes() {
        let ledger = Ledger::open_in_memory().unwrap();
        let first = ledger
            .register_artifact(ArtifactRegistration {
                bytes: b"identical bytes",
                media_type: "text/plain",
                storage_path: "objects/first",
                retention: RetentionClass::Canonical,
                created_at: at(10),
            })
            .unwrap();
        let retry = ledger
            .register_artifact(ArtifactRegistration {
                bytes: b"identical bytes",
                media_type: "application/octet-stream",
                storage_path: "objects/retry",
                retention: RetentionClass::Scratch,
                created_at: at(20),
            })
            .unwrap();

        assert_eq!(retry, first);
        assert_eq!(first.size_bytes, 15);
        assert_eq!(first.media_type, "text/plain");
        assert_eq!(first.storage_path, "objects/first");
        let table_columns: Vec<String> = ledger
            .connection()
            .prepare("PRAGMA table_info(artifacts)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!table_columns.iter().any(|column| column == "bytes"));
    }
}
