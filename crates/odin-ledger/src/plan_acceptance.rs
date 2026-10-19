//! Durable operator plan acceptance bound to the exact structural plan.
//!
//! Projection rebuilds preserve the `plan_acceptance` extension kind because acceptance has no other source table.
//!
//! A record binds the accepted run to the structural fingerprint of its plan
//! (objective plus ordered todo definitions; never mutable progress state)
//! and to the authenticated local operator that approved it. [`Ledger::plan_is_accepted`]
//! therefore answers a question about the present: a plan that merely exists
//! is never accepted, and any structural change silently voids the record
//! until a real operator re-approves. Inherited acceptance additionally pins
//! the approved parent structure, so a child stays valid only while its
//! approved parent structure is unchanged and the parent's own acceptance
//! still holds. Lineage is bounded and cycle-free by construction.

use std::collections::BTreeSet;

use odin_domain::RunId;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::plan::{load_plan, plan_structure_fingerprint, stale_plan};
use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

pub const PLAN_ACCEPTANCE_SCHEMA_VERSION: u16 = 1;

/// The `materialized_status` object kind that owns acceptance records.
pub const PLAN_ACCEPTANCE_OBJECT_KIND: &str = "plan_acceptance";

/// The maximum number of acceptance records in one lineage. Deeper or cyclic
/// lineages are rejected at write time and never validate at read time.
pub const MAX_LINEAGE_DEPTH: usize = 64;

const ACTOR_MAX_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAcceptance {
    pub run_id: RunId,
    /// The plan revision observed when the operator approved; informational,
    /// because progress advances the revision without changing the structure.
    pub plan_revision: i64,
    pub fingerprint: String,
    /// The authenticated local operator identity, e.g. `device:<uuid>` or
    /// `inherit:<parent run>`.
    pub actor: String,
    pub accepted_at: OffsetDateTime,
    pub parent: Option<InheritedParent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InheritedParent {
    pub run_id: RunId,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanAcceptanceWire {
    pub schema_version: u16,
    pub run_id: RunId,
    pub plan_revision: i64,
    pub fingerprint: String,
    pub actor: String,
    pub accepted_at: String,
    pub parent: Option<ParentWire>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParentWire {
    pub run_id: RunId,
    pub fingerprint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanAcceptanceWireParts {
    schema_version: u16,
    run_id: RunId,
    plan_revision: i64,
    fingerprint: String,
    actor: String,
    accepted_at: String,
    parent: Option<ParentWire>,
}

impl<'de> Deserialize<'de> for PlanAcceptanceWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = PlanAcceptanceWireParts::deserialize(deserializer)?;
        if parts.schema_version != PLAN_ACCEPTANCE_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported plan acceptance schema version {}",
                parts.schema_version
            )));
        }
        validate_plan_revision(parts.plan_revision).map_err(serde::de::Error::custom)?;
        validate_fingerprint(&parts.fingerprint).map_err(serde::de::Error::custom)?;
        validate_actor(&parts.actor).map_err(serde::de::Error::custom)?;
        decode_utc(&parts.accepted_at).map_err(serde::de::Error::custom)?;
        if let Some(parent) = &parts.parent {
            validate_fingerprint(&parent.fingerprint).map_err(serde::de::Error::custom)?;
        }
        Ok(Self {
            schema_version: parts.schema_version,
            run_id: parts.run_id,
            plan_revision: parts.plan_revision,
            fingerprint: parts.fingerprint,
            actor: parts.actor,
            accepted_at: parts.accepted_at,
            parent: parts.parent,
        })
    }
}

impl TryFrom<&PlanAcceptance> for PlanAcceptanceWire {
    type Error = LedgerError;

    fn try_from(record: &PlanAcceptance) -> LedgerResult<Self> {
        validate_plan_revision(record.plan_revision)?;
        validate_fingerprint(&record.fingerprint)?;
        validate_actor(&record.actor)?;
        if let Some(parent) = &record.parent {
            validate_fingerprint(&parent.fingerprint)?;
        }
        Ok(Self {
            schema_version: PLAN_ACCEPTANCE_SCHEMA_VERSION,
            run_id: record.run_id.clone(),
            plan_revision: record.plan_revision,
            fingerprint: record.fingerprint.clone(),
            actor: record.actor.clone(),
            accepted_at: encode_utc(record.accepted_at)?,
            parent: record.parent.as_ref().map(|parent| ParentWire {
                run_id: parent.run_id.clone(),
                fingerprint: parent.fingerprint.clone(),
            }),
        })
    }
}

impl PlanAcceptanceWire {
    pub fn into_acceptance(self) -> LedgerResult<PlanAcceptance> {
        if self.schema_version != PLAN_ACCEPTANCE_SCHEMA_VERSION {
            return Err(LedgerError::invalid_data(format!(
                "unsupported plan acceptance schema version {}",
                self.schema_version
            )));
        }
        validate_plan_revision(self.plan_revision)?;
        validate_fingerprint(&self.fingerprint)?;
        validate_actor(&self.actor)?;
        if let Some(parent) = &self.parent {
            validate_fingerprint(&parent.fingerprint)?;
        }
        Ok(PlanAcceptance {
            run_id: self.run_id,
            plan_revision: self.plan_revision,
            fingerprint: self.fingerprint,
            actor: self.actor,
            accepted_at: decode_utc(&self.accepted_at)?,
            parent: self.parent.map(|parent| InheritedParent {
                run_id: parent.run_id,
                fingerprint: parent.fingerprint,
            }),
        })
    }
}

fn validate_fingerprint(value: &str) -> LedgerResult<()> {
    odin_domain::Digest::parse(value).map_err(|error| {
        LedgerError::invalid_data_caused_by(
            format!("acceptance fingerprint {value:?} is not a canonical BLAKE3 digest"),
            error,
        )
    })?;
    Ok(())
}

fn validate_actor(actor: &str) -> LedgerResult<()> {
    let bytes = actor.as_bytes();
    let well_formed = !bytes.is_empty()
        && bytes.len() <= ACTOR_MAX_BYTES
        && bytes
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if !well_formed {
        return Err(LedgerError::invalid_data(
            "acceptance actor must be a bounded identifier-like operator identity".into(),
        ));
    }
    Ok(())
}

fn validate_plan_revision(revision: i64) -> LedgerResult<()> {
    if revision < 1 {
        return Err(LedgerError::invalid_data(
            "acceptance plan revision must be positive".into(),
        ));
    }
    Ok(())
}

impl Ledger {
    /// Reads the acceptance record of one run's plan, if any. The record is a
    /// fact about the past; only [`Ledger::plan_is_accepted`] decides whether
    /// it still holds for the current plan structure.
    pub fn plan_acceptance(&self, run_id: &RunId) -> LedgerResult<Option<PlanAcceptance>> {
        read_acceptance_row(self.connection(), run_id)
    }

    /// Whether the run's plan is genuinely accepted right now: a durable
    /// acceptance record must exist and match the plan's current structural
    /// fingerprint and — for inherited acceptance — its approved parent
    /// structure must be unchanged and the parent's own acceptance must still
    /// hold. A plan that merely exists is never accepted.
    pub fn plan_is_accepted(&self, run_id: &RunId) -> LedgerResult<bool> {
        acceptance_holds(self.connection(), run_id)
    }

    /// Records real operator acceptance of the exact current plan structure.
    ///
    /// `expected_revision` names the plan revision the operator reviewed; a
    /// mismatch is rejected exactly like a stale aggregate replacement.
    /// `actor` is the authenticated local operator identity. A previous
    /// record for the run is replaced: accepting again is a new approval of
    /// the then-current structure.
    pub fn accept_plan(
        &mut self,
        run_id: &RunId,
        expected_revision: i64,
        actor: &str,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        validate_actor(actor)?;
        self.with_tx(|tx| {
            let plan = load_plan(tx, run_id)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: run_id.to_string(),
            })?;
            if plan.revision != expected_revision {
                return Err(stale_plan(tx, run_id, expected_revision)?);
            }
            write_acceptance(
                tx,
                &PlanAcceptance {
                    run_id: run_id.clone(),
                    plan_revision: plan.revision,
                    fingerprint: plan_structure_fingerprint(&plan),
                    actor: actor.to_owned(),
                    accepted_at: now,
                    parent: None,
                },
            )
        })
    }

    /// Inherits operator acceptance for a child plan from an already-accepted
    /// parent plan.
    ///
    /// The parent must currently hold a valid acceptance (its whole lineage
    /// included), and the child record pins the exact parent structure it was
    /// accepted against, so any later parent structure change voids the
    /// child. Lineage that would close a cycle or exceed the bounded depth is
    /// rejected.
    pub fn inherit_plan_acceptance(
        &mut self,
        parent_run: &RunId,
        child_run: &RunId,
        now: OffsetDateTime,
    ) -> LedgerResult<()> {
        if parent_run == child_run {
            return Err(LedgerError::invalid_data(
                "plan acceptance lineage cannot be self-referential".to_owned(),
            ));
        }
        self.with_tx(|tx| {
            let child_plan = load_plan(tx, child_run)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: child_run.to_string(),
            })?;
            let parent_plan = load_plan(tx, parent_run)?.ok_or_else(|| LedgerError::NotFound {
                kind: "plan",
                id: parent_run.to_string(),
            })?;
            verify_accepted_lineage(tx, parent_run, child_run)?;
            write_acceptance(
                tx,
                &PlanAcceptance {
                    run_id: child_run.clone(),
                    plan_revision: child_plan.revision,
                    fingerprint: plan_structure_fingerprint(&child_plan),
                    actor: format!("inherit:{parent_run}"),
                    accepted_at: now,
                    parent: Some(InheritedParent {
                        run_id: parent_run.clone(),
                        fingerprint: plan_structure_fingerprint(&parent_plan),
                    }),
                },
            )
        })
    }
}

/// Reads and decodes one acceptance row, cross-checking the denormalized
/// columns against the canonical JSON record.
fn read_acceptance_row(
    connection: &Connection,
    run_id: &RunId,
) -> LedgerResult<Option<PlanAcceptance>> {
    let row = connection
        .query_row(
            "SELECT revision, status_json FROM materialized_status
             WHERE object_kind = ?1 AND object_id = ?2",
            params![PLAN_ACCEPTANCE_OBJECT_KIND, run_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((plan_revision, status_json)) = row else {
        return Ok(None);
    };
    let wire: PlanAcceptanceWire = serde_json::from_str(&status_json)?;
    if wire.run_id != *run_id {
        return Err(LedgerError::invalid_data(format!(
            "acceptance record {} names run {}",
            run_id, wire.run_id
        )));
    }
    if wire.plan_revision != plan_revision {
        return Err(LedgerError::invalid_data(format!(
            "acceptance record {run_id} revision {plan_revision} disagrees with its JSON revision {}",
            wire.plan_revision
        )));
    }
    wire.into_acceptance().map(Some)
}

fn write_acceptance(connection: &Connection, record: &PlanAcceptance) -> LedgerResult<()> {
    let wire = PlanAcceptanceWire::try_from(record)?;
    let status_json = serde_json::to_string(&wire)?;
    let accepted_at = encode_utc(record.accepted_at)?;
    let source = format!(
        "source:plan_acceptance:{}:revision:{}",
        record.run_id, record.plan_revision
    );
    connection.execute(
        "INSERT INTO materialized_status (
             object_kind, object_id, revision, status_json,
             source_event_id, updated_at, stale_after
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
         ON CONFLICT(object_kind, object_id) DO UPDATE SET
             revision = excluded.revision,
             status_json = excluded.status_json,
             source_event_id = excluded.source_event_id,
             updated_at = excluded.updated_at,
             stale_after = NULL",
        params![
            PLAN_ACCEPTANCE_OBJECT_KIND,
            record.run_id.to_string(),
            record.plan_revision,
            status_json,
            source,
            accepted_at,
        ],
    )?;
    Ok(())
}

/// Walks the acceptance lineage from `start` upward. Every record must match
/// its plan's current structure, every pinned parent structure must be
/// unchanged, and the lineage must stay within the bounded depth. Returns
/// `Ok(false)` for every doubt: missing records, changed structures, cyclic
/// or over-deep lineages never validate.
fn acceptance_holds(connection: &Connection, start: &RunId) -> LedgerResult<bool> {
    let mut visited: BTreeSet<RunId> = BTreeSet::new();
    visited.insert(start.clone());
    let mut current = start.clone();
    for _ in 0..MAX_LINEAGE_DEPTH {
        let Some(record) = read_acceptance_row(connection, &current)? else {
            return Ok(false);
        };
        let Some(plan) = load_plan(connection, &current)? else {
            return Ok(false);
        };
        if plan_structure_fingerprint(&plan) != record.fingerprint {
            return Ok(false);
        }
        let Some(parent) = record.parent else {
            return Ok(true);
        };
        if !visited.insert(parent.run_id.clone()) {
            return Ok(false);
        }
        let Some(parent_plan) = load_plan(connection, &parent.run_id)? else {
            return Ok(false);
        };
        if plan_structure_fingerprint(&parent_plan) != parent.fingerprint {
            return Ok(false);
        }
        current = parent.run_id;
    }
    Ok(false)
}

/// Verifies, inside the caller's transaction, that `parent` roots a currently
/// valid acceptance lineage that never reaches `child` and leaves room for
/// the child record within the bounded depth.
fn verify_accepted_lineage(
    connection: &Connection,
    parent: &RunId,
    child: &RunId,
) -> LedgerResult<()> {
    let mut visited: BTreeSet<RunId> = BTreeSet::new();
    visited.insert(parent.clone());
    let mut current = parent.clone();
    let mut depth = 0_usize;
    loop {
        if depth == MAX_LINEAGE_DEPTH {
            return Err(LedgerError::Conflict(format!(
                "plan acceptance lineage above {parent} exceeds the {MAX_LINEAGE_DEPTH}-record bound"
            )));
        }
        if current == *child {
            return Err(LedgerError::Conflict(format!(
                "plan acceptance lineage would close a cycle at {child}"
            )));
        }
        let Some(record) = read_acceptance_row(connection, &current)? else {
            return Err(LedgerError::Conflict(format!(
                "parent plan {current} is not accepted: no acceptance record exists"
            )));
        };
        let Some(plan) = load_plan(connection, &current)? else {
            return Err(LedgerError::Conflict(format!(
                "parent plan {current} disappeared from the ledger"
            )));
        };
        if plan_structure_fingerprint(&plan) != record.fingerprint {
            return Err(LedgerError::Conflict(format!(
                "parent plan {current} changed after its acceptance was recorded"
            )));
        }
        depth += 1;
        let Some(inherited) = record.parent else {
            break;
        };
        if !visited.insert(inherited.run_id.clone()) {
            return Err(LedgerError::Conflict(format!(
                "plan acceptance lineage above {parent} is cyclic"
            )));
        }
        current = inherited.run_id;
    }
    if depth + 1 > MAX_LINEAGE_DEPTH {
        return Err(LedgerError::Conflict(format!(
            "plan acceptance lineage would exceed the {MAX_LINEAGE_DEPTH}-record bound at {child}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use odin_domain::{RunId, TodoId};
    use time::OffsetDateTime;

    use super::{Ledger, LedgerError, PLAN_ACCEPTANCE_OBJECT_KIND};
    use crate::plan::{Plan, TodoSpec, TodoStatus};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    const AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn run(name: &str) -> RunId {
        RunId::new(format!("run:{name}")).unwrap()
    }

    /// Seeds the lane and run rows the plan foreign keys require. Attempt
    /// numbers are unique per lane, so every run names its own.
    fn seed_run_at(ledger: &Ledger, run_id: &RunId, attempt: i64) {
        ledger
            .connection()
            .execute_batch(&format!(
                "INSERT OR IGNORE INTO lanes(
                     lane_id, seat_id, template_id, backend, status, created_by,
                     created_at, updated_at
                 ) VALUES (
                     'lane:accept-test', 'seat:test', 'template:test', 'local_omp',
                     'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );
                 INSERT INTO runs(
                     run_id, lane_id, attempt_number, status, input_hash,
                     created_at, updated_at
                 ) VALUES (
                     '{run_id}', 'lane:accept-test', {attempt}, 'pending', 'hash',
                     '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );"
            ))
            .unwrap();
    }

    fn seed_run(ledger: &Ledger, run_id: &RunId) {
        seed_run_at(ledger, run_id, 1);
    }

    fn draft_plan(ledger: &mut Ledger, run_id: &RunId, objective: &str) -> Plan {
        ledger.replace_plan(run_id, objective, &[], 0, AT).unwrap()
    }

    fn database_path() -> PathBuf {
        let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "odin-ledger-plan-acceptance-{}-{sequence}.sqlite3",
            std::process::id()
        ))
    }

    #[test]
    fn a_plan_that_merely_exists_is_never_accepted() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("draft-only");
        seed_run(&ledger, &run_id);
        draft_plan(&mut ledger, &run_id, "unapproved objective");

        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
        assert!(ledger.plan_acceptance(&run_id).unwrap().is_none());

        // A stale expected revision is rejected exactly like a stale
        // aggregate replacement, and nothing gets recorded.
        let error = ledger
            .accept_plan(
                &run_id,
                2,
                "device:00000000-0000-4000-8000-000000000001",
                AT,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            LedgerError::StaleActor {
                expected_revision: 2,
                actual_revision: 1,
                ..
            }
        ));
    }

    #[test]
    fn acceptance_persists_and_survives_reopen() {
        let path = database_path();
        let run_id = run("durable-accept");
        {
            let mut ledger = Ledger::open(&path).unwrap();
            seed_run(&ledger, &run_id);
            let plan = draft_plan(&mut ledger, &run_id, "durable objective");
            ledger
                .accept_plan(
                    &run_id,
                    plan.revision,
                    "device:00000000-0000-4000-8000-000000000001",
                    AT,
                )
                .unwrap();
            assert!(ledger.plan_is_accepted(&run_id).unwrap());
        }

        let reopened = Ledger::open(&path).unwrap();
        assert!(reopened.plan_is_accepted(&run_id).unwrap());
        let record = reopened.plan_acceptance(&run_id).unwrap().unwrap();
        assert_eq!(record.actor, "device:00000000-0000-4000-8000-000000000001");
        assert_eq!(record.plan_revision, 1);
        assert!(record.parent.is_none());
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_structural_change_voids_acceptance_until_reapproved() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("structural");
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "approved objective");
        ledger
            .accept_plan(&run_id, plan.revision, "operator:console", AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());

        // A replacement that changes the objective changes the structure.
        let changed = ledger
            .replace_plan(&run_id, "rewritten objective", &[], plan.revision, AT)
            .unwrap();
        assert!(!ledger.plan_is_accepted(&run_id).unwrap());
        // The record still exists; it no longer holds for the new structure.
        assert!(ledger.plan_acceptance(&run_id).unwrap().is_some());

        // Re-approval of the current structure is a new genuine acceptance.
        ledger
            .accept_plan(&run_id, changed.revision, "operator:console", AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());

        // Re-writing the identical structure does not change the approved
        // intent, so the earlier acceptance keeps holding.
        let rewritten = ledger
            .replace_plan(&run_id, "rewritten objective", &[], changed.revision, AT)
            .unwrap();
        assert_ne!(rewritten.revision, changed.revision);
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
    }

    #[test]
    fn progress_updates_never_void_acceptance() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("progress");
        seed_run(&ledger, &run_id);
        let todo_id = TodoId::new("todo:progress").unwrap();
        let plan = ledger
            .replace_plan(
                &run_id,
                "approved objective",
                &[TodoSpec {
                    id: todo_id.clone(),
                    title: "first todo".to_owned(),
                    status: TodoStatus::Pending,
                }],
                0,
                AT,
            )
            .unwrap();
        ledger
            .accept_plan(&run_id, plan.revision, "operator:console", AT)
            .unwrap();

        let progressed = ledger
            .transition_todo(&run_id, &todo_id, TodoStatus::Active, plan.revision, AT)
            .unwrap();
        assert_eq!(progressed.revision, plan.revision + 1);
        assert!(ledger.plan_is_accepted(&run_id).unwrap());

        // Renaming a todo definition is a structural change, not progress.
        let renamed = ledger
            .replace_plan(
                &run_id,
                "approved objective",
                &[TodoSpec {
                    id: todo_id,
                    title: "renamed todo".to_owned(),
                    status: TodoStatus::Active,
                }],
                progressed.revision,
                AT,
            )
            .unwrap();
        ledger
            .accept_plan(&run_id, renamed.revision, "operator:console", AT)
            .unwrap();
        let _completed = ledger
            .transition_todo(
                &run_id,
                &TodoId::new("todo:progress").unwrap(),
                TodoStatus::Completed,
                renamed.revision,
                AT,
            )
            .unwrap();
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
    }

    #[test]
    fn inherited_acceptance_follows_a_currently_accepted_parent() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let parent_id = run("inherit-parent");
        let child_id = run("inherit-child");
        seed_run_at(&ledger, &parent_id, 1);
        seed_run_at(&ledger, &child_id, 2);

        // Without an accepted parent there is nothing to inherit.
        let parent = draft_plan(&mut ledger, &parent_id, "parent objective");
        let child = draft_plan(&mut ledger, &child_id, "child objective");
        let error = ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::Conflict(_)));

        ledger
            .accept_plan(&parent_id, parent.revision, "operator:console", AT)
            .unwrap();
        ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
        let record = ledger.plan_acceptance(&child_id).unwrap().unwrap();
        let inherited = record.parent.as_ref().unwrap();
        assert_eq!(inherited.run_id, parent_id);
        assert_eq!(record.actor, format!("inherit:{parent_id}"));

        // Changing the approved parent structure voids the child. While the
        // parent itself is not yet re-approved, even its own gate is shut.
        let changed_parent = ledger
            .replace_plan(&parent_id, "parent objective v2", &[], parent.revision, AT)
            .unwrap();
        assert!(!ledger.plan_is_accepted(&parent_id).unwrap());
        assert!(!ledger.plan_is_accepted(&child_id).unwrap());

        // Re-approving the parent reopens the parent gate — but the child
        // still pins the old parent structure, so it stays void.
        ledger
            .accept_plan(&parent_id, changed_parent.revision, "operator:console", AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&parent_id).unwrap());
        assert!(!ledger.plan_is_accepted(&child_id).unwrap());

        // Re-inheritance pins the new parent structure and reopens the child.
        ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap();
        assert!(ledger.plan_is_accepted(&child_id).unwrap());
        drop(child);
    }

    #[test]
    fn lineage_rejects_cycles_and_unbounded_depth() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let first = run("lineage-first");
        let second = run("lineage-second");
        seed_run_at(&ledger, &first, 1);
        seed_run_at(&ledger, &second, 2);
        let first_plan = draft_plan(&mut ledger, &first, "first");
        let _second_plan = draft_plan(&mut ledger, &second, "second");
        ledger
            .accept_plan(&first, first_plan.revision, "operator:console", AT)
            .unwrap();
        ledger.inherit_plan_acceptance(&first, &second, AT).unwrap();

        // A direct self-reference is rejected before any walk.
        let error = ledger
            .inherit_plan_acceptance(&second, &second, AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::InvalidData { .. }));

        // Closing the loop back onto the ancestor is rejected.
        let error = ledger
            .inherit_plan_acceptance(&second, &first, AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::Conflict(_)));
        assert!(ledger.plan_is_accepted(&first).unwrap());

        // Deeper than the bounded lineage is unbounded and rejected; the
        // boundary itself stays usable.
        let mut previous = second.clone();
        for attempt in 3.. {
            let next = run(format!("lineage-{attempt}").as_str());
            seed_run_at(&ledger, &next, attempt);
            let _delegated = draft_plan(&mut ledger, &next, "delegated");
            ledger
                .inherit_plan_acceptance(&previous, &next, AT)
                .unwrap_or_else(|error| {
                    panic!("inheritance {attempt} must stay bounded-valid: {error}")
                });
            assert!(ledger.plan_is_accepted(&next).unwrap());
            previous = next;
            if attempt == 64 {
                break;
            }
        }
        let beyond = run("lineage-beyond");
        seed_run_at(&ledger, &beyond, 65);
        let _beyond_plan = draft_plan(&mut ledger, &beyond, "delegated");
        let error = ledger
            .inherit_plan_acceptance(&previous, &beyond, AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::Conflict(_)));
        assert!(!ledger.plan_is_accepted(&beyond).unwrap());
    }

    #[test]
    fn acceptance_rows_survive_a_materialized_rebuild() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("rebuild");
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "approved objective");
        ledger
            .accept_plan(&run_id, plan.revision, "operator:console", AT)
            .unwrap();

        let rebuilt = ledger.rebuild_materialized_status().unwrap();
        assert!(rebuilt > 0);
        assert!(ledger.plan_is_accepted(&run_id).unwrap());
        let (kind, revision, stale_after) = ledger
            .connection()
            .query_row(
                "SELECT object_kind, revision, stale_after FROM materialized_status
                 WHERE object_id = ?1",
                [run_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(kind, PLAN_ACCEPTANCE_OBJECT_KIND);
        assert_eq!(revision, plan.revision);
        assert_eq!(stale_after, None);
    }

    #[test]
    fn accept_plan_requires_a_real_actor_and_current_revision() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let run_id = run("guards");
        seed_run(&ledger, &run_id);
        let plan = draft_plan(&mut ledger, &run_id, "objective");

        let error = ledger
            .accept_plan(&run_id, plan.revision, "", AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::InvalidData { .. }));
        let error = ledger
            .accept_plan(&run_id, plan.revision, "operator console!", AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::InvalidData { .. }));
        let error = ledger
            .accept_plan(&run_id, 99, "operator:console", AT)
            .unwrap_err();
        assert!(matches!(error, LedgerError::StaleActor { .. }));
        assert!(ledger.plan_acceptance(&run_id).unwrap().is_none());
    }

    #[test]
    fn acceptance_wire_roundtrips_and_rejects_corrupt_records() {
        use super::{ParentWire, PlanAcceptanceWire, PLAN_ACCEPTANCE_SCHEMA_VERSION};
        let mut ledger = Ledger::open_in_memory().unwrap();
        let parent_id = run("wire-parent");
        let child_id = run("wire-child");
        seed_run_at(&ledger, &parent_id, 1);
        seed_run_at(&ledger, &child_id, 2);
        let parent = draft_plan(&mut ledger, &parent_id, "parent");
        let _child = draft_plan(&mut ledger, &child_id, "child");
        ledger
            .accept_plan(&parent_id, parent.revision, "operator:console", AT)
            .unwrap();
        ledger
            .inherit_plan_acceptance(&parent_id, &child_id, AT)
            .unwrap();
        let record = ledger.plan_acceptance(&child_id).unwrap().unwrap();

        let wire = PlanAcceptanceWire::try_from(&record).unwrap();
        assert_eq!(wire.schema_version, PLAN_ACCEPTANCE_SCHEMA_VERSION);
        assert_eq!(wire.clone().into_acceptance().unwrap(), record);
        let encoded = serde_json::to_string(&wire).unwrap();
        assert!(encoded.contains(r#""schemaVersion":1"#));
        let decoded: PlanAcceptanceWire = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.into_acceptance().unwrap(), record);

        let mut wrong_version = wire.clone();
        wrong_version.schema_version = 99;
        assert!(wrong_version.into_acceptance().is_err());

        let mut bad_actor = wire.clone();
        bad_actor.actor = "operator console!".to_owned();
        assert!(serde_json::from_str::<PlanAcceptanceWire>(
            &serde_json::to_string(&bad_actor).unwrap()
        )
        .is_err());

        // A malformed (but well-linked) parent fingerprint is rejected at
        // the wire boundary; a well-formed one decodes and is judged later
        // by the lineage walk, never by decoding alone.
        let mut bad_parent = wire;
        bad_parent.parent = Some(ParentWire {
            run_id: parent_id,
            fingerprint: "not-a-digest".to_owned(),
        });
        assert!(serde_json::from_str::<PlanAcceptanceWire>(
            &serde_json::to_string(&bad_parent).unwrap()
        )
        .is_err());
    }
}
