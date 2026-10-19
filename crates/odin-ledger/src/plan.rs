use std::str::FromStr;

use odin_domain::{RunId, TodoId};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

pub const PLAN_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoStatus {
    Pending,
    Active,
    Blocked,
    Completed,
    Cancelled,
}

impl TodoStatus {
    const fn as_db(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }

    fn from_db(value: &str) -> LedgerResult<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "blocked" => Ok(Self::Blocked),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(LedgerError::invalid_data(format!(
                "unknown todo status {value:?}"
            ))),
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Pending => matches!(next, Self::Active | Self::Cancelled),
            Self::Active => matches!(next, Self::Blocked | Self::Completed | Self::Cancelled),
            Self::Blocked => matches!(next, Self::Active | Self::Cancelled),
            Self::Completed | Self::Cancelled => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TodoSpec {
    pub id: TodoId,
    pub title: String,
    pub status: TodoStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Todo {
    pub id: TodoId,
    pub ordinal: i64,
    pub title: String,
    pub status: TodoStatus,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    pub run_id: RunId,
    pub revision: i64,
    pub objective: String,
    pub todos: Vec<Todo>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanWire {
    pub schema_version: u16,
    pub run_id: RunId,
    pub revision: i64,
    pub objective: String,
    pub todos: Vec<TodoWire>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TodoWire {
    pub id: TodoId,
    pub ordinal: i64,
    pub title: String,
    pub status: TodoStatus,
    pub updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanWireParts {
    schema_version: u16,
    run_id: RunId,
    revision: i64,
    objective: String,
    todos: Vec<TodoWireParts>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TodoWireParts {
    id: TodoId,
    ordinal: i64,
    title: String,
    status: TodoStatus,
    updated_at: String,
}

impl<'de> Deserialize<'de> for PlanWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = PlanWireParts::deserialize(deserializer)?;
        if parts.schema_version != PLAN_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported plan schema version {}",
                parts.schema_version
            )));
        }
        validate_plan_header(parts.revision, &parts.objective).map_err(serde::de::Error::custom)?;
        for todo in &parts.todos {
            validate_todo_fields(&todo.id, todo.ordinal, &todo.title)
                .map_err(serde::de::Error::custom)?;
        }
        decode_utc(&parts.created_at).map_err(serde::de::Error::custom)?;
        decode_utc(&parts.updated_at).map_err(serde::de::Error::custom)?;
        Ok(Self {
            schema_version: parts.schema_version,
            run_id: parts.run_id,
            revision: parts.revision,
            objective: parts.objective,
            todos: parts
                .todos
                .into_iter()
                .map(|todo| TodoWire {
                    id: todo.id,
                    ordinal: todo.ordinal,
                    title: todo.title,
                    status: todo.status,
                    updated_at: todo.updated_at,
                })
                .collect(),
            created_at: parts.created_at,
            updated_at: parts.updated_at,
        })
    }
}

impl TryFrom<&Plan> for PlanWire {
    type Error = LedgerError;

    fn try_from(plan: &Plan) -> LedgerResult<Self> {
        validate_plan_record(plan)?;
        Ok(Self {
            schema_version: PLAN_SCHEMA_VERSION,
            run_id: plan.run_id.clone(),
            revision: plan.revision,
            objective: plan.objective.clone(),
            todos: plan
                .todos
                .iter()
                .map(|todo| {
                    Ok(TodoWire {
                        id: todo.id.clone(),
                        ordinal: todo.ordinal,
                        title: todo.title.clone(),
                        status: todo.status,
                        updated_at: encode_utc(todo.updated_at)?,
                    })
                })
                .collect::<LedgerResult<Vec<_>>>()?,
            created_at: encode_utc(plan.created_at)?,
            updated_at: encode_utc(plan.updated_at)?,
        })
    }
}

impl PlanWire {
    pub fn into_plan(self) -> LedgerResult<Plan> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            return Err(LedgerError::invalid_data(format!(
                "unsupported plan schema version {}",
                self.schema_version
            )));
        }
        let plan = Plan {
            run_id: self.run_id,
            revision: self.revision,
            objective: self.objective,
            todos: self
                .todos
                .into_iter()
                .map(|todo| {
                    Ok(Todo {
                        id: todo.id,
                        ordinal: todo.ordinal,
                        title: todo.title,
                        status: todo.status,
                        updated_at: decode_utc(&todo.updated_at)?,
                    })
                })
                .collect::<LedgerResult<Vec<_>>>()?,
            created_at: decode_utc(&self.created_at)?,
            updated_at: decode_utc(&self.updated_at)?,
        };
        validate_plan_record(&plan)?;
        Ok(plan)
    }
}

fn validate_plan_record(plan: &Plan) -> LedgerResult<()> {
    validate_plan_header(plan.revision, &plan.objective)?;
    for todo in &plan.todos {
        validate_todo_fields(&todo.id, todo.ordinal, &todo.title)?;
    }
    Ok(())
}

fn validate_plan_header(revision: i64, objective: &str) -> LedgerResult<()> {
    if revision < 1 {
        return Err(LedgerError::invalid_data(
            "plan revision must be positive".into(),
        ));
    }
    if objective.trim().is_empty() {
        return Err(LedgerError::invalid_data(
            "plan objective must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_todo_fields(id: &TodoId, ordinal: i64, title: &str) -> LedgerResult<()> {
    if ordinal < 0 {
        return Err(LedgerError::invalid_data(
            "todo ordinals must not be negative".into(),
        ));
    }
    if title.trim().is_empty() {
        return Err(LedgerError::invalid_data(format!(
            "todo {id} has an empty title"
        )));
    }
    Ok(())
}

/// Shared validation keeps preflight admission and transactional execution consistent.
fn validate_replace_inputs(
    expected_revision: i64,
    objective: &str,
    todos: &[TodoSpec],
) -> LedgerResult<()> {
    if expected_revision < 0 {
        return Err(LedgerError::invalid_data(
            "plan revision must not be negative".to_owned(),
        ));
    }
    if objective.trim().is_empty() {
        return Err(LedgerError::invalid_data(
            "plan objective must not be empty".to_owned(),
        ));
    }
    validate_todos(todos)
}

const STRUCTURE_FINGERPRINT_DOMAIN: &[u8] = b"odin-plan-structure-v1";

fn push_structure_field(buffer: &mut Vec<u8>, field: &[u8]) {
    let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(field);
}

/// Computes the structural fingerprint of a plan: the objective plus the
/// complete ordered todo definitions (identifier and title, in ordinal
/// order), canonically length-prefixed and BLAKE3-digested.
///
/// Mutable progress state — todo statuses, timestamps, and the revision
/// counter — is deliberately excluded. Changing the objective or any todo
/// definition therefore invalidates a recorded acceptance, while mere
/// progress on the approved structure never does.
pub fn plan_structure_fingerprint(plan: &Plan) -> String {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(STRUCTURE_FINGERPRINT_DOMAIN);
    push_structure_field(&mut encoded, plan.objective.as_bytes());
    let todo_count = u64::try_from(plan.todos.len()).unwrap_or(u64::MAX);
    encoded.extend_from_slice(&todo_count.to_be_bytes());
    for todo in &plan.todos {
        push_structure_field(&mut encoded, todo.id.as_str().as_bytes());
        push_structure_field(&mut encoded, todo.title.as_bytes());
    }
    odin_domain::Digest::hash(&encoded).to_string()
}

impl Ledger {
    /// Checks replacement inputs and revision without writing, using execution's
    /// validation errors; absent plans require revision zero.
    pub fn prepare_plan_replace(
        &self,
        run_id: &RunId,
        objective: &str,
        todos: &[TodoSpec],
        expected_revision: i64,
    ) -> LedgerResult<()> {
        validate_replace_inputs(expected_revision, objective, todos)?;
        match self.plan(run_id)? {
            Some(plan) if plan.revision != expected_revision => {
                Err(stale_plan(self.connection(), run_id, expected_revision)?)
            }
            None if expected_revision != 0 => {
                Err(stale_plan(self.connection(), run_id, expected_revision)?)
            }
            _ => Ok(()),
        }
    }

    /// Checks revision, todo membership, and allowed transitions without writing,
    /// using execution's validation errors.
    pub fn prepare_todo_transition(
        &self,
        run_id: &RunId,
        todo_id: &TodoId,
        next: TodoStatus,
        expected_revision: i64,
    ) -> LedgerResult<()> {
        if expected_revision < 0 {
            return Err(LedgerError::invalid_data(
                "plan revision must not be negative".to_owned(),
            ));
        }
        let plan = self.plan(run_id)?;
        if plan.as_ref().map(|plan| plan.revision) != Some(expected_revision) {
            return Err(stale_plan(self.connection(), run_id, expected_revision)?);
        }
        let plan = plan.expect("revision equality implies the plan exists");
        let current = plan
            .todos
            .iter()
            .find(|todo| &todo.id == todo_id)
            .map(|todo| todo.status)
            .ok_or_else(|| {
                LedgerError::invalid_data(format!(
                    "todo {todo_id} does not belong to plan {run_id}"
                ))
            })?;
        if !current.can_transition_to(next) {
            return Err(LedgerError::invalid_data(format!(
                "todo {todo_id} cannot transition from {} to {}",
                current.as_db(),
                next.as_db()
            )));
        }
        Ok(())
    }

    /// Replaces the objective and complete ordered todo set as one revisioned aggregate.
    ///
    /// Revision zero means that no plan may exist yet. Every later replacement must name the
    /// currently observed revision.
    pub fn replace_plan(
        &mut self,
        run_id: &RunId,
        objective: &str,
        todos: &[TodoSpec],
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> LedgerResult<Plan> {
        validate_replace_inputs(expected_revision, objective, todos)?;
        let timestamp = encode_utc(now)?;
        self.with_tx(|tx| {
            replace_aggregate(tx, run_id, objective, todos, expected_revision, &timestamp)
        })
    }

    pub fn transition_todo(
        &mut self,
        run_id: &RunId,
        todo_id: &TodoId,
        next: TodoStatus,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> LedgerResult<Plan> {
        let timestamp = encode_utc(now)?;
        self.with_tx(|tx| {
            let changed = tx.execute(
                "UPDATE plans
                 SET revision = revision + 1, updated_at = ?1
                 WHERE run_id = ?2 AND revision = ?3",
                (&timestamp, run_id.as_str(), expected_revision),
            )?;
            if changed == 0 {
                return Err(stale_plan(tx, run_id, expected_revision)?);
            }
            let current = load_todo_status(tx, run_id, todo_id)?;
            if !current.can_transition_to(next) {
                return Err(LedgerError::invalid_data(format!(
                    "todo {todo_id} cannot transition from {} to {}",
                    current.as_db(),
                    next.as_db()
                )));
            }

            let changed = tx.execute(
                "UPDATE plan_items
                 SET status = ?1, updated_at = ?2
                 WHERE run_id = ?3 AND item_id = ?4",
                (next.as_db(), &timestamp, run_id.as_str(), todo_id.as_str()),
            )?;
            if changed != 1 {
                return Err(LedgerError::invalid_data(format!(
                    "todo {todo_id} does not belong to plan {run_id}"
                )));
            }
            load_plan(tx, run_id)?.ok_or_else(|| {
                LedgerError::invalid_data(format!("plan {run_id} disappeared during transition"))
            })
        })
    }

    pub fn plan(&self, run_id: &RunId) -> LedgerResult<Option<Plan>> {
        load_plan(self.connection(), run_id)
    }
}

fn validate_todos(todos: &[TodoSpec]) -> LedgerResult<()> {
    let mut ids = std::collections::BTreeSet::new();
    for todo in todos {
        if todo.title.trim().is_empty() {
            return Err(LedgerError::invalid_data(format!(
                "todo {} has an empty title",
                todo.id
            )));
        }
        if !ids.insert(todo.id.clone()) {
            return Err(LedgerError::invalid_data(format!(
                "todo {} occurs more than once",
                todo.id
            )));
        }
    }
    Ok(())
}

fn replace_aggregate(
    tx: &Transaction<'_>,
    run_id: &RunId,
    objective: &str,
    todos: &[TodoSpec],
    expected_revision: i64,
    timestamp: &str,
) -> LedgerResult<Plan> {
    let changed = if expected_revision == 0 {
        tx.execute(
            "INSERT INTO plans(run_id, revision, objective, created_at, updated_at)
             VALUES (?1, 1, ?2, ?3, ?3)
             ON CONFLICT(run_id) DO NOTHING",
            (run_id.to_string(), objective, timestamp),
        )?
    } else {
        tx.execute(
            "UPDATE plans
             SET revision = revision + 1, objective = ?1, updated_at = ?2
             WHERE run_id = ?3 AND revision = ?4",
            (objective, timestamp, run_id.to_string(), expected_revision),
        )?
    };
    if changed == 0 {
        return Err(stale_plan(tx, run_id, expected_revision)?);
    }

    tx.execute(
        "DELETE FROM plan_items WHERE run_id = ?1",
        [run_id.to_string()],
    )?;
    let mut statement = tx.prepare(
        "INSERT INTO plan_items(run_id, item_id, ordinal, title, status, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (ordinal, todo) in todos.iter().enumerate() {
        statement.execute((
            run_id.to_string(),
            todo.id.to_string(),
            i64::try_from(ordinal).map_err(|error| {
                LedgerError::invalid_data_caused_by("plan contains too many todos", error)
            })?,
            &todo.title,
            todo.status.as_db(),
            timestamp,
        ))?;
    }
    drop(statement);

    load_plan(tx, run_id)?.ok_or_else(|| {
        LedgerError::invalid_data(format!("plan {run_id} disappeared during replacement"))
    })
}

pub(crate) fn load_plan(connection: &Connection, run_id: &RunId) -> LedgerResult<Option<Plan>> {
    let raw = connection
        .query_row(
            "SELECT revision, objective, created_at, updated_at
             FROM plans WHERE run_id = ?1",
            [run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((revision, objective, created_at, updated_at)) = raw else {
        return Ok(None);
    };

    let mut statement = connection.prepare(
        "SELECT item_id, ordinal, title, status, updated_at
         FROM plan_items WHERE run_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map([run_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut todos = Vec::new();
    for row in rows {
        let (id, ordinal, title, status, todo_updated_at) = row?;
        todos.push(Todo {
            id: TodoId::from_str(&id)
                .map_err(|error| LedgerError::invalid_data_caused_by("invalid todo id", error))?,
            ordinal,
            title,
            status: TodoStatus::from_db(&status)?,
            updated_at: decode_utc(&todo_updated_at)?,
        });
    }
    let plan = Plan {
        run_id: run_id.clone(),
        revision,
        objective,
        todos,
        created_at: decode_utc(&created_at)?,
        updated_at: decode_utc(&updated_at)?,
    };
    validate_plan_record(&plan)?;
    Ok(Some(plan))
}

fn load_todo_status(
    connection: &Connection,
    run_id: &RunId,
    todo_id: &TodoId,
) -> LedgerResult<TodoStatus> {
    let status = connection
        .query_row(
            "SELECT status FROM plan_items WHERE run_id = ?1 AND item_id = ?2",
            (run_id.to_string(), todo_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            LedgerError::invalid_data(format!("todo {todo_id} does not belong to plan {run_id}"))
        })?;
    TodoStatus::from_db(&status)
}

pub(crate) fn stale_plan(
    connection: &Connection,
    run_id: &RunId,
    expected_revision: i64,
) -> LedgerResult<LedgerError> {
    let actual_revision = connection
        .query_row(
            "SELECT revision FROM plans WHERE run_id = ?1",
            [run_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    Ok(LedgerError::StaleActor {
        actor: format!("plan:{run_id}"),
        expected_revision,
        actual_revision,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use odin_domain::{RunId, TodoId};
    use time::OffsetDateTime;

    use super::{Ledger, LedgerError, TodoSpec, TodoStatus};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn ids() -> (RunId, TodoId) {
        (
            RunId::new("run:plan-test").unwrap(),
            TodoId::new("todo:first").unwrap(),
        )
    }

    fn seed_run(ledger: &Ledger, run_id: &RunId) {
        ledger
            .connection()
            .execute_batch(&format!(
                "INSERT INTO lanes(
                    lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at
                 ) VALUES (
                    'lane:plan-test', 'seat:test', 'template:test', 'local_omp', 'desired',
                    'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );
                 INSERT INTO runs(
                    run_id, lane_id, attempt_number, status, input_hash, created_at, updated_at
                 ) VALUES (
                    '{run_id}', 'lane:plan-test', 1, 'pending', 'hash',
                    '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
                 );"
            ))
            .unwrap();
    }

    fn database_path() -> PathBuf {
        let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "odin-ledger-plan-{}-{sequence}.sqlite3",
            std::process::id()
        ))
    }

    #[test]
    fn stale_plan_is_rejected_and_plan_survives_reopen() {
        let path = database_path();
        let (run_id, todo_id) = ids();
        {
            let mut ledger = Ledger::open(&path).unwrap();
            seed_run(&ledger, &run_id);
            let plan = ledger
                .replace_plan(
                    &run_id,
                    "durable objective",
                    &[TodoSpec {
                        id: todo_id.clone(),
                        title: "first durable todo".to_owned(),
                        status: TodoStatus::Pending,
                    }],
                    0,
                    OffsetDateTime::UNIX_EPOCH,
                )
                .unwrap();
            assert_eq!(plan.revision, 1);

            let error = ledger
                .replace_plan(
                    &run_id,
                    "stale replacement",
                    &[],
                    0,
                    OffsetDateTime::UNIX_EPOCH,
                )
                .unwrap_err();
            assert!(matches!(
                error,
                LedgerError::StaleActor {
                    expected_revision: 0,
                    actual_revision: 1,
                    ..
                }
            ));
        }

        let reopened = Ledger::open(&path).unwrap();
        let plan = reopened.plan(&run_id).unwrap().unwrap();
        assert_eq!(plan.objective, "durable objective");
        assert_eq!(plan.todos.len(), 1);
        assert_eq!(plan.todos[0].id, todo_id);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn prepare_apis_refuse_stale_missing_and_illegal_without_writing() {
        let run_id = RunId::new("run:prepare:one").unwrap();
        let todo_id = TodoId::new("todo:prepare:one").unwrap();
        let mut ledger = Ledger::open_in_memory().unwrap();
        seed_run(&ledger, &run_id);
        let todos = || {
            vec![TodoSpec {
                id: todo_id.clone(),
                title: "one".to_owned(),
                status: TodoStatus::Pending,
            }]
        };
        assert!(matches!(
            ledger.prepare_plan_replace(&run_id, "   ", &todos(), 0),
            Err(LedgerError::InvalidData { .. })
        ));
        // First revision on a missing plan is admitted; a nonzero observed
        // revision on a missing plan refuses with the same StaleActor
        // variant execution's conditional update returns (actual 0).
        ledger
            .prepare_plan_replace(&run_id, "objective", &todos(), 0)
            .expect("a first revision prepares clean");
        assert!(matches!(
            ledger.prepare_plan_replace(&run_id, "objective", &todos(), 3),
            Err(LedgerError::StaleActor {
                expected_revision: 3,
                actual_revision: 0,
                ..
            })
        ));
        ledger
            .replace_plan(
                &run_id,
                "objective",
                &todos(),
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("seed the plan");
        // Stale observed revision refuses — the same StaleActor variant
        // execution returns — and writes nothing.
        assert!(matches!(
            ledger.prepare_plan_replace(&run_id, "objective", &todos(), 0),
            Err(LedgerError::StaleActor {
                expected_revision: 0,
                actual_revision: 1,
                ..
            })
        ));
        assert_eq!(ledger.plan(&run_id).unwrap().unwrap().revision, 1);
        // Missing todo refuses with the same InvalidData membership error
        // execution's transaction returns.
        assert!(matches!(
            ledger.prepare_todo_transition(
                &run_id,
                &TodoId::new("todo:prepare:absent").unwrap(),
                TodoStatus::Active,
                1
            ),
            Err(LedgerError::InvalidData { .. })
        ));
        // Complete the todo before checking that completed -> active is rejected.
        ledger
            .transition_todo(
                &run_id,
                &todo_id,
                TodoStatus::Active,
                1,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("activate the todo");
        ledger
            .transition_todo(
                &run_id,
                &todo_id,
                TodoStatus::Completed,
                2,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("complete the todo");
        assert!(matches!(
            ledger.prepare_todo_transition(&run_id, &todo_id, TodoStatus::Active, 3),
            Err(LedgerError::InvalidData { .. })
        ));
        assert_eq!(
            ledger.plan(&run_id).unwrap().unwrap().todos[0].status,
            TodoStatus::Completed,
            "a refused preparation never transitions"
        );
    }
}
