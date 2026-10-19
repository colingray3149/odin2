use std::str::FromStr;

use odin_domain::{ArtifactId, CheckpointId, CommandId, Digest, RunId};
use rusqlite::{Connection, OptionalExtension};
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointSpec {
    pub id: CheckpointId,
    pub run_id: RunId,
    pub command_id: Option<CommandId>,
    pub compatibility_key: String,
    pub artifact_ref: ArtifactId,
    pub artifact_digest: Digest,
    pub state_digest: Digest,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub run_id: RunId,
    pub command_id: Option<CommandId>,
    pub revision: i64,
    pub compatibility_key: String,
    pub artifact_ref: ArtifactId,
    pub artifact_digest: Digest,
    pub state_digest: Digest,
    pub created_at: OffsetDateTime,
    pub committed_at: Option<OffsetDateTime>,
    pub rollback_of: Option<CheckpointId>,
}

impl Checkpoint {
    pub const fn is_committed(&self) -> bool {
        self.committed_at.is_some()
    }
}

impl Ledger {
    /// Reuses an identical checkpoint on retry so an interrupted create/commit pair
    /// can resume; conflicting content under the same ID is rejected.
    pub fn create_checkpoint(&mut self, spec: &CheckpointSpec) -> LedgerResult<Checkpoint> {
        if spec.compatibility_key.trim().is_empty() {
            return Err(LedgerError::invalid_data(
                "checkpoint compatibility key must not be empty".to_owned(),
            ));
        }
        let created_at = encode_utc(spec.created_at)?;
        self.with_tx(|tx| {
            let inserted = tx.execute(
                "INSERT INTO checkpoints(checkpoint_id, run_id, command_id, revision, compatibility_key, artifact_ref, artifact_digest, state_hash, created_at, committed, committed_at, rollback_of) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 0, NULL, NULL)
                 ON CONFLICT(checkpoint_id) DO NOTHING",
                (spec.id.to_string(), spec.run_id.to_string(), spec.command_id.as_ref().map(ToString::to_string), &spec.compatibility_key, spec.artifact_ref.to_string(), spec.artifact_digest.to_string(), spec.state_digest.to_string(), &created_at),
            )?;
            if inserted == 1 {
                return required_checkpoint(tx, &spec.id);
            }
            let existing = required_checkpoint(tx, &spec.id)?;
            if matches_spec(&existing, spec) {
                return Ok(existing);
            }
            Err(LedgerError::Conflict(format!(
                "checkpoint {} already records different durable state",
                spec.id
            )))
        })
    }

    /// Commits once, preserving the original stamp when the caller retries
    /// either the original expected revision or the already-committed row.
    pub fn commit_checkpoint(
        &mut self,
        checkpoint_id: &CheckpointId,
        expected_revision: i64,
        committed_at: OffsetDateTime,
    ) -> LedgerResult<Checkpoint> {
        let timestamp = encode_utc(committed_at)?;
        self.with_tx(|tx| {
            let changed = tx.execute("UPDATE checkpoints SET committed = 1, committed_at = ?1, revision = revision + 1 WHERE checkpoint_id = ?2 AND revision = ?3 AND committed = 0", (&timestamp, checkpoint_id.to_string(), expected_revision))?;
            if changed == 1 {
                return required_checkpoint(tx, checkpoint_id);
            }
            let existing = required_checkpoint(tx, checkpoint_id)?;
            if existing.is_committed()
                && (existing.revision == expected_revision
                    || (expected_revision > 0
                        && expected_revision.checked_add(1) == Some(existing.revision)))
            {
                return Ok(existing);
            }
            Err(checkpoint_mutation_error(&existing, expected_revision, "commit"))
        })
    }

    /// Records a committed rollback checkpoint by copying the exact compatibility and state/artifact
    /// digests of a committed ancestor. The guarded INSERT makes the lineage and revision check one
    /// atomic database action. A replayed rollback converges onto the row it already created —
    /// same identity, same source content — instead of failing; anything else is a typed error.
    pub fn rollback_checkpoint(
        &mut self,
        source_id: &CheckpointId,
        rollback_id: &CheckpointId,
        command_id: Option<&CommandId>,
        expected_source_revision: i64,
        created_at: OffsetDateTime,
    ) -> LedgerResult<Checkpoint> {
        let timestamp = encode_utc(created_at)?;
        self.with_tx(|tx| {
            let changed = tx.execute(
                "INSERT INTO checkpoints(checkpoint_id, run_id, command_id, revision, compatibility_key, artifact_ref, artifact_digest, state_hash, created_at, committed, committed_at, rollback_of)
                 SELECT ?1, run_id, ?2, 1, compatibility_key, artifact_ref, artifact_digest, state_hash, ?3, 1, ?3, checkpoint_id
                 FROM checkpoints WHERE checkpoint_id = ?4 AND revision = ?5 AND committed = 1
                 ON CONFLICT(checkpoint_id) DO NOTHING",
                (rollback_id.to_string(), command_id.map(ToString::to_string), &timestamp, source_id.to_string(), expected_source_revision),
            )?;
            if changed == 1 {
                return required_checkpoint(tx, rollback_id);
            }
            let source = required_checkpoint(tx, source_id)?;
            if source.revision != expected_source_revision || !source.is_committed() {
                return Err(checkpoint_mutation_error(
                    &source,
                    expected_source_revision,
                    "roll back",
                ));
            }
            if let Some(existing) = load_checkpoint(tx, rollback_id)? {
                if matches_rollback(&existing, &source, source_id, command_id) {
                    return Ok(existing);
                }
                return Err(LedgerError::Conflict(format!(
                    "checkpoint {rollback_id} already records a different rollback"
                )));
            }
            Err(checkpoint_mutation_error(&source, expected_source_revision, "roll back"))
        })
    }

    pub fn checkpoint(&self, checkpoint_id: &CheckpointId) -> LedgerResult<Option<Checkpoint>> {
        load_checkpoint(self.connection(), checkpoint_id)
    }
}

fn required_checkpoint(
    connection: &Connection,
    checkpoint_id: &CheckpointId,
) -> LedgerResult<Checkpoint> {
    load_checkpoint(connection, checkpoint_id)?.ok_or_else(|| {
        LedgerError::invalid_data(format!("checkpoint {checkpoint_id} does not exist"))
    })
}

fn checkpoint_mutation_error(
    checkpoint: &Checkpoint,
    expected_revision: i64,
    operation: &str,
) -> LedgerError {
    if checkpoint.revision != expected_revision {
        return LedgerError::StaleActor {
            actor: format!("checkpoint:{}", checkpoint.id),
            expected_revision,
            actual_revision: checkpoint.revision,
        };
    }
    LedgerError::invalid_data(format!(
        "checkpoint {} cannot {operation} from its current state",
        checkpoint.id
    ))
}

/// A checkpoint row's content never changes after creation, so a replayed
/// creation converges exactly when the durable row already carries its content.
/// Revision and commit stamp may advance during a resumed creation, but an
/// existing rollback is never adopted as a plain creation.
fn matches_spec(record: &Checkpoint, spec: &CheckpointSpec) -> bool {
    record.rollback_of.is_none()
        && record.run_id == spec.run_id
        && record.command_id == spec.command_id
        && record.compatibility_key == spec.compatibility_key
        && record.artifact_ref == spec.artifact_ref
        && record.artifact_digest == spec.artifact_digest
        && record.state_digest == spec.state_digest
}

/// A replayed rollback converges only onto a row that is exactly this
/// rollback: born committed, pointing at this source, carrying this
/// source's immutable content, and recorded for this command.
fn matches_rollback(
    record: &Checkpoint,
    source: &Checkpoint,
    source_id: &CheckpointId,
    command_id: Option<&CommandId>,
) -> bool {
    record.is_committed()
        && record.rollback_of.as_ref() == Some(source_id)
        && record.command_id.as_ref() == command_id
        && record.run_id == source.run_id
        && record.compatibility_key == source.compatibility_key
        && record.artifact_ref == source.artifact_ref
        && record.artifact_digest == source.artifact_digest
        && record.state_digest == source.state_digest
}

fn load_checkpoint(
    connection: &Connection,
    checkpoint_id: &CheckpointId,
) -> LedgerResult<Option<Checkpoint>> {
    type Raw = (
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
    );
    let raw: Option<Raw> = connection.query_row(
        "SELECT run_id, command_id, revision, compatibility_key, artifact_ref, artifact_digest, state_hash, created_at, committed, committed_at, rollback_of FROM checkpoints WHERE checkpoint_id = ?1",
        [checkpoint_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?)),
    ).optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if (raw.8 == 1) != raw.9.is_some() {
        return Err(LedgerError::invalid_data(format!(
            "checkpoint {checkpoint_id} has inconsistent commit state"
        )));
    }
    Ok(Some(Checkpoint {
        id: checkpoint_id.clone(),
        run_id: RunId::from_str(&raw.0).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid checkpoint run id", error)
        })?,
        command_id: raw
            .1
            .map(|value| {
                CommandId::from_str(&value).map_err(|error| {
                    LedgerError::invalid_data_caused_by("invalid checkpoint command id", error)
                })
            })
            .transpose()?,
        revision: raw.2,
        compatibility_key: raw.3,
        artifact_ref: ArtifactId::from_str(&raw.4).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid checkpoint artifact id", error)
        })?,
        artifact_digest: Digest::from_str(&raw.5).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid checkpoint artifact digest", error)
        })?,
        state_digest: Digest::from_str(&raw.6).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid checkpoint state digest", error)
        })?,
        created_at: decode_utc(&raw.7)?,
        committed_at: raw.9.as_deref().map(decode_utc).transpose()?,
        rollback_of: raw
            .10
            .map(|value| {
                CheckpointId::from_str(&value).map_err(|error| {
                    LedgerError::invalid_data_caused_by("invalid checkpoint rollback id", error)
                })
            })
            .transpose()?,
    }))
}

#[cfg(test)]
mod tests {
    use super::{CheckpointSpec, Ledger};
    use crate::LedgerError;
    use odin_domain::{ArtifactId, CheckpointId, CommandId, Digest, RunId};
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use time::OffsetDateTime;

    fn at(offset_seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_312_000 + offset_seconds).expect("timestamp")
    }

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "odin-checkpoint-{label}-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    fn seed_control_rows(ledger: &Ledger) {
        ledger.connection().execute_batch(
            "INSERT OR IGNORE INTO lanes(lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at) VALUES ('lane:checkpoint-test', 'seat:test', 'template:test', 'local_omp', 'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');
             INSERT OR IGNORE INTO runs(run_id, lane_id, attempt_number, status, input_hash, created_at, updated_at) VALUES ('run:checkpoint-test', 'lane:checkpoint-test', 1, 'pending', 'hash', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');",
        )
        .unwrap();
    }

    /// A real file-backed ledger so every drop is a close and every `seeded`
    /// call a fresh open across the durable boundary.
    fn seeded(path: &Path) -> Ledger {
        let ledger = Ledger::open(path).expect("open file-backed ledger");
        seed_control_rows(&ledger);
        ledger
    }

    fn resume_spec(id: &str, state: &[u8]) -> CheckpointSpec {
        CheckpointSpec {
            id: CheckpointId::new(id).unwrap(),
            run_id: RunId::new("run:checkpoint-test").unwrap(),
            command_id: None,
            compatibility_key: "runtime:v1".to_owned(),
            artifact_ref: ArtifactId::new("artifact:checkpoint").unwrap(),
            artifact_digest: Digest::hash(b"artifact"),
            state_digest: Digest::hash(state),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn rollback_preserves_digest_lineage() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        seed_control_rows(&ledger);
        let source_id = CheckpointId::new("checkpoint:source").unwrap();
        let state_digest = Digest::hash(b"state");
        let artifact_digest = Digest::hash(b"artifact");
        ledger
            .create_checkpoint(&CheckpointSpec {
                id: source_id.clone(),
                run_id: RunId::new("run:checkpoint-test").unwrap(),
                command_id: None,
                compatibility_key: "runtime:v1".to_owned(),
                artifact_ref: ArtifactId::new("artifact:checkpoint").unwrap(),
                artifact_digest,
                state_digest,
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .unwrap();
        ledger
            .commit_checkpoint(&source_id, 1, OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let rollback_id = CheckpointId::new("checkpoint:rollback").unwrap();
        let rollback = ledger
            .rollback_checkpoint(
                &source_id,
                &rollback_id,
                None,
                2,
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(rollback.rollback_of, Some(source_id));
        assert_eq!(rollback.state_digest, state_digest);
        assert_eq!(rollback.artifact_digest, artifact_digest);
        assert!(rollback.is_committed());
    }

    /// The create→commit pair spans two durable transactions, so a restart
    /// between them is an ordinary boundary. On a reopened file-backed
    /// ledger, replaying the exact creation resumes the pending row, the
    /// interrupted commit completes with the original identity, and a full
    /// replay converges to the same single durable row without restamping.
    #[test]
    fn interrupted_checkpoint_resumes_once_across_reopen() {
        let path = temp_path("checkpoint-resume");
        let spec = resume_spec("checkpoint:resume", b"state");
        let pending = {
            let mut ledger = seeded(&path);
            let pending = ledger.create_checkpoint(&spec).unwrap();
            assert!(!pending.is_committed());
            pending
        };
        let committed = {
            let mut ledger = seeded(&path);
            let resumed = ledger.create_checkpoint(&spec).unwrap();
            assert_eq!(resumed.revision, pending.revision);
            assert!(!resumed.is_committed());
            let committed = ledger
                .commit_checkpoint(&resumed.id, resumed.revision, at(1))
                .unwrap();
            assert!(committed.is_committed());
            committed
        };
        let mut ledger = seeded(&path);
        let durable = ledger
            .checkpoint(&spec.id)
            .unwrap()
            .expect("durable checkpoint");
        assert!(durable.is_committed());
        assert_eq!(durable.committed_at, committed.committed_at);
        assert_eq!(durable.revision, committed.revision);
        let retransmitted = ledger
            .commit_checkpoint(&spec.id, pending.revision, at(2))
            .unwrap();
        assert_eq!(
            retransmitted, durable,
            "lost acknowledgment must not repeat the commit"
        );
        assert!(matches!(
            ledger.commit_checkpoint(&spec.id, 0, at(2)),
            Err(LedgerError::StaleActor { .. })
        ));
        let replayed = ledger.create_checkpoint(&spec).unwrap();
        assert_eq!(replayed.revision, durable.revision);
        let recommitted = ledger
            .commit_checkpoint(&replayed.id, replayed.revision, at(2))
            .unwrap();
        assert_eq!(
            recommitted.committed_at, committed.committed_at,
            "replay must not restamp the durable commit"
        );
        assert_eq!(recommitted.revision, durable.revision);
        drop(ledger);
        fs::remove_file(&path).ok();
    }

    /// A different durable record under a claimed identity is a typed
    /// conflict that leaves the row untouched, and a creation whose
    /// transaction fails (foreign key) rolls back to no residue, so the
    /// identity stays creatable.
    #[test]
    fn conflicting_identity_and_failed_creates_leave_the_durable_record_intact() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        seed_control_rows(&ledger);
        let spec = resume_spec("checkpoint:identity", b"state");
        let created = ledger.create_checkpoint(&spec).unwrap();
        let mut conflicting = spec.clone();
        conflicting.state_digest = Digest::hash(b"different-state");
        let error = ledger.create_checkpoint(&conflicting).unwrap_err();
        assert!(matches!(error, LedgerError::Conflict(_)));
        let durable = ledger
            .checkpoint(&spec.id)
            .unwrap()
            .expect("original row survives the conflict");
        assert_eq!(durable.state_digest, created.state_digest);
        let mut orphan = resume_spec("checkpoint:orphan", b"state");
        orphan.run_id = RunId::new("run:missing").unwrap();
        assert!(ledger.create_checkpoint(&orphan).is_err());
        assert!(
            ledger.checkpoint(&orphan.id).unwrap().is_none(),
            "a failed creation must strand no row"
        );
        let lawful = resume_spec("checkpoint:orphan", b"state");
        assert_eq!(ledger.create_checkpoint(&lawful).unwrap().id, orphan.id);
    }

    /// A rollback that already durably happened replays to the same
    /// committed row instead of failing; a replay recording a different
    /// command is refused and leaves the durable row untouched.
    #[test]
    fn rollback_replay_converges_and_mismatches_are_refused() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        seed_control_rows(&ledger);
        let source_id = CheckpointId::new("checkpoint:source").unwrap();
        ledger
            .create_checkpoint(&resume_spec("checkpoint:source", b"state"))
            .unwrap();
        ledger
            .commit_checkpoint(&source_id, 1, OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let rollback_id = CheckpointId::new("checkpoint:rollback").unwrap();
        let first = ledger
            .rollback_checkpoint(&source_id, &rollback_id, None, 2, at(1))
            .unwrap();
        assert!(first.is_committed());
        let replay = ledger
            .rollback_checkpoint(&source_id, &rollback_id, None, 2, at(2))
            .unwrap();
        assert_eq!(replay.committed_at, first.committed_at);
        assert_eq!(replay.revision, first.revision);
        assert!(matches!(
            ledger.rollback_checkpoint(&source_id, &rollback_id, None, 1, at(2)),
            Err(LedgerError::StaleActor { .. })
        ));
        assert!(matches!(
            ledger.create_checkpoint(&resume_spec("checkpoint:rollback", b"state")),
            Err(LedgerError::Conflict(_))
        ));
        let other = CommandId::new("command:other").unwrap();
        let error = ledger
            .rollback_checkpoint(&source_id, &rollback_id, Some(&other), 2, at(3))
            .unwrap_err();
        assert!(matches!(error, LedgerError::Conflict(_)));
        let durable = ledger
            .checkpoint(&rollback_id)
            .unwrap()
            .expect("durable rollback");
        assert_eq!(durable.command_id, None);
        assert_eq!(durable.committed_at, first.committed_at);
    }
}
