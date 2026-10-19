//! Browser-control snapshots survive projection rebuilds via [`BROWSER_CONTROL_STATE_KIND`].
//! The browser validates payloads; the ledger enforces size limits and revision CAS
//! so stale processes cannot overwrite a replacement host's state.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

/// Browser-control object kind in `materialized_status`.
pub const BROWSER_CONTROL_STATE_KIND: &str = "browser_control";
pub const MAX_BROWSER_CONTROL_STATE_BYTES: usize = 16 * 1024;
const MAX_BROWSER_CONTROL_OBJECT_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserControlStateRow {
    pub object_id: String,
    /// CAS revision; the caller must validate that the browser payload carries the same value.
    pub revision: i64,
    pub state_json: String,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenBrowserControlState {
    Created(BrowserControlStateRow),
    Existing(BrowserControlStateRow),
}

impl OpenBrowserControlState {
    pub fn row(&self) -> &BrowserControlStateRow {
        match self {
            Self::Created(row) | Self::Existing(row) => row,
        }
    }

    pub fn into_row(self) -> BrowserControlStateRow {
        match self {
            Self::Created(row) | Self::Existing(row) => row,
        }
    }
}

impl Ledger {
    pub fn browser_control_state(
        &self,
        object_id: &str,
    ) -> LedgerResult<Option<BrowserControlStateRow>> {
        validate_object_id(object_id)?;
        load_browser_control_state(self.connection(), object_id)
    }

    /// Atomically creates one browser control row at revision one or returns
    /// the pre-existing row. A replay never resets existing state.
    pub fn open_browser_control_state(
        &mut self,
        object_id: &str,
        initial_state_json: &str,
        at: OffsetDateTime,
    ) -> LedgerResult<OpenBrowserControlState> {
        validate_object_id(object_id)?;
        validate_state_json(initial_state_json)?;
        let timestamp = encode_utc(at)?;
        self.with_tx(|transaction| {
            let changed = transaction.execute(
                "INSERT INTO materialized_status
                    (object_kind, object_id, revision, status_json, source_event_id, updated_at)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5)
                 ON CONFLICT(object_kind, object_id) DO NOTHING",
                params![
                    BROWSER_CONTROL_STATE_KIND,
                    object_id,
                    initial_state_json,
                    format!("browser_control:{object_id}:init"),
                    &timestamp,
                ],
            )?;
            let row = load_browser_control_state(transaction, object_id)?.ok_or_else(|| {
                LedgerError::invalid_data(format!(
                    "browser control state {object_id} disappeared after open"
                ))
            })?;
            if changed == 1 {
                Ok(OpenBrowserControlState::Created(row))
            } else {
                Ok(OpenBrowserControlState::Existing(row))
            }
        })
    }

    /// Compare-and-set persistence of one browser control payload. The write
    /// lands only when the durable row is still at `expected_revision`; the
    /// revision advances by exactly one. A stale or absent row fails without
    /// mutation.
    pub fn cas_browser_control_state(
        &mut self,
        object_id: &str,
        expected_revision: i64,
        state_json: &str,
        at: OffsetDateTime,
    ) -> LedgerResult<BrowserControlStateRow> {
        validate_object_id(object_id)?;
        validate_state_json(state_json)?;
        if expected_revision < 1 {
            return Err(LedgerError::invalid_data(
                "browser control expected revision must be positive".to_owned(),
            ));
        }
        let next_revision = expected_revision.checked_add(1).ok_or_else(|| {
            LedgerError::invalid_data(format!(
                "browser control state {object_id} revision overflow"
            ))
        })?;
        let timestamp = encode_utc(at)?;
        self.with_tx(|transaction| {
            let changed = transaction.execute(
                "UPDATE materialized_status
                 SET status_json = ?1, updated_at = ?2, source_event_id = ?3, revision = ?4
                 WHERE object_kind = ?5 AND object_id = ?6 AND revision = ?7",
                params![
                    state_json,
                    &timestamp,
                    format!("browser_control:{object_id}:revision:{next_revision}"),
                    next_revision,
                    BROWSER_CONTROL_STATE_KIND,
                    object_id,
                    expected_revision,
                ],
            )?;
            if changed == 0 {
                let current = load_browser_control_state(transaction, object_id)?;
                return match current {
                    Some(row) => Err(LedgerError::StaleActor {
                        actor: format!("browser_control:{object_id}"),
                        expected_revision,
                        actual_revision: row.revision,
                    }),
                    None => Err(LedgerError::NotFound {
                        kind: "browser_control",
                        id: object_id.to_owned(),
                    }),
                };
            }
            let row = load_browser_control_state(transaction, object_id)?.ok_or_else(|| {
                LedgerError::invalid_data(format!(
                    "browser control state {object_id} disappeared after CAS"
                ))
            })?;
            if row.revision != next_revision || row.state_json != state_json {
                return Err(LedgerError::invalid_data(format!(
                    "browser control state {object_id} did not round-trip its CAS"
                )));
            }
            Ok(row)
        })
    }
}

fn load_browser_control_state(
    connection: &Connection,
    object_id: &str,
) -> LedgerResult<Option<BrowserControlStateRow>> {
    let raw: Option<(i64, String, String)> = connection
        .query_row(
            "SELECT revision, status_json, updated_at
             FROM materialized_status
             WHERE object_kind = ?1 AND object_id = ?2",
            params![BROWSER_CONTROL_STATE_KIND, object_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((revision, state_json, updated_at)) = raw else {
        return Ok(None);
    };
    validate_state_json(&state_json)?;
    Ok(Some(BrowserControlStateRow {
        object_id: object_id.to_owned(),
        revision,
        state_json,
        updated_at: decode_utc(&updated_at)?,
    }))
}

fn validate_object_id(object_id: &str) -> LedgerResult<()> {
    if object_id.trim().is_empty() || object_id.len() > MAX_BROWSER_CONTROL_OBJECT_ID_BYTES {
        return Err(LedgerError::invalid_data(
            "browser control object id is empty or over its bound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_state_json(state_json: &str) -> LedgerResult<()> {
    if state_json.len() > MAX_BROWSER_CONTROL_STATE_BYTES {
        return Err(LedgerError::invalid_data(
            "browser control state json exceeds its byte bound".to_owned(),
        ));
    }
    let value: Value = serde_json::from_str(state_json)?;
    if !value.is_object() {
        return Err(LedgerError::invalid_data(
            "browser control state json must be an object".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "00000000-0000-4000-8000-000000000008";

    fn at(second: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_312_000 + second).expect("fixture timestamp")
    }

    #[test]
    fn browser_control_state_reopens_and_cas_fences_stale_writer() {
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        let created = ledger
            .open_browser_control_state(SESSION, r#"{"schema":"one"}"#, at(0))
            .expect("create");
        let OpenBrowserControlState::Created(created) = created else {
            panic!("first open must create");
        };
        assert_eq!(created.revision, 1);

        let reopened = ledger
            .open_browser_control_state(SESSION, r#"{"schema":"ignored"}"#, at(1))
            .expect("reopen");
        let OpenBrowserControlState::Existing(reopened) = reopened else {
            panic!("second open must return existing");
        };
        assert_eq!(reopened, created);

        let advanced = ledger
            .cas_browser_control_state(SESSION, 1, r#"{"schema":"two"}"#, at(2))
            .expect("CAS");
        assert_eq!(advanced.revision, 2);
        assert_eq!(advanced.state_json, r#"{"schema":"two"}"#);

        assert!(matches!(
            ledger.cas_browser_control_state(SESSION, 1, r#"{"schema":"stale"}"#, at(3)),
            Err(LedgerError::StaleActor {
                expected_revision: 1,
                actual_revision: 2,
                ..
            })
        ));
        assert_eq!(
            ledger
                .browser_control_state(SESSION)
                .expect("read")
                .expect("row"),
            advanced
        );
    }

    #[test]
    fn browser_control_state_survives_projection_rebuild() {
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        let created = ledger
            .open_browser_control_state(SESSION, r#"{"schema":"one"}"#, at(0))
            .expect("create")
            .into_row();
        ledger.rebuild_materialized_status().expect("rebuild");
        assert_eq!(
            ledger
                .browser_control_state(SESSION)
                .expect("read")
                .expect("row"),
            created
        );
    }

    #[test]
    fn browser_control_state_rejects_non_object_or_oversized_payload() {
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        assert!(matches!(
            ledger.open_browser_control_state(SESSION, "[]", at(0)),
            Err(LedgerError::InvalidData { .. })
        ));
        let oversized = format!(
            r#"{{"value":"{}"}}"#,
            "x".repeat(MAX_BROWSER_CONTROL_STATE_BYTES)
        );
        assert!(matches!(
            ledger.open_browser_control_state(SESSION, &oversized, at(0)),
            Err(LedgerError::InvalidData { .. })
        ));
    }
}
